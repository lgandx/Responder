# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Partial C706.pdf + [MS-RPCE] implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/SecureAuthCorp/impacket/tree/master/tests/SMB_RPC
#
# ToDo:
# [ ] Take out all the security provider stuff out of here (e.g. RPC_C_AUTHN_WINNT)
#     and put it elsewhere. This will make the coder cleaner and easier to add
#     more SSP (e.g. NETLOGON)
#

import logging
import socket
import sys
from binascii import unhexlify
from Cryptodome.Cipher import ARC4

from impacket import ntlm, LOG
from impacket.structure import Structure, pack, unpack
from impacket.krb5 import kerberosv5, gssapi
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup
from impacket.dcerpc.v5.dtypes import UCHAR, ULONG, USHORT
from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket import hresult_errors
from threading import Thread

# MS/RPC Constants
MSRPC_REQUEST = 0x00
MSRPC_PING = 0x01
MSRPC_RESPONSE = 0x02
MSRPC_FAULT = 0x03
MSRPC_WORKING = 0x04
MSRPC_NOCALL = 0x05
MSRPC_REJECT = 0x06
MSRPC_ACK = 0x07
MSRPC_CL_CANCEL = 0x08
MSRPC_FACK = 0x09
MSRPC_CANCELACK = 0x0A
MSRPC_BIND = 0x0B
MSRPC_BINDACK = 0x0C
MSRPC_BINDNAK = 0x0D
MSRPC_ALTERCTX = 0x0E
MSRPC_ALTERCTX_R = 0x0F
MSRPC_AUTH3 = 0x10
MSRPC_SHUTDOWN = 0x11
MSRPC_CO_CANCEL = 0x12
MSRPC_ORPHANED = 0x13
MSRPC_RTS = 0x14

# MS/RPC Packet Flags
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02

# For PDU types bind, bind_ack, alter_context, and
# alter_context_resp, this flag MUST be interpreted as PFC_SUPPORT_HEADER_SIGN
MSRPC_SUPPORT_SIGN = 0x04

# For the
# remaining PDU types, this flag MUST be interpreted as PFC_PENDING_CANCEL.
MSRPC_PENDING_CANCEL = 0x04

PFC_RESERVED_1 = 0x08
PFC_CONC_MPX = 0x10
PFC_DID_NOT_EXECUTE = 0x20
PFC_MAYBE = 0x40
PFC_OBJECT_UUID = 0x80

# Auth Types - Security Providers
RPC_C_AUTHN_NONE = 0x00
RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
RPC_C_AUTHN_WINNT = 0x0A
RPC_C_AUTHN_GSS_SCHANNEL = 0x0E
RPC_C_AUTHN_GSS_KERBEROS = 0x10
RPC_C_AUTHN_NETLOGON = 0x44
RPC_C_AUTHN_DEFAULT = 0xFF

# Auth Levels
RPC_C_AUTHN_LEVEL_NONE = 1
RPC_C_AUTHN_LEVEL_CONNECT = 2
RPC_C_AUTHN_LEVEL_CALL = 3
RPC_C_AUTHN_LEVEL_PKT = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6

# Reasons for rejection of a context element, included in bind_ack result reason
rpc_provider_reason = {
    0: "reason_not_specified",
    1: "abstract_syntax_not_supported",
    2: "proposed_transfer_syntaxes_not_supported",
    3: "local_limit_exceeded",
    4: "protocol_version_not_specified",
    8: "authentication_type_not_recognized",
    9: "invalid_checksum",
}

MSRPC_CONT_RESULT_ACCEPT = 0
MSRPC_CONT_RESULT_USER_REJECT = 1
MSRPC_CONT_RESULT_PROV_REJECT = 2

# Results of a presentation context negotiation
rpc_cont_def_result = {0: "acceptance", 1: "user_rejection", 2: "provider_rejection"}

# status codes, references:
# https://docs.microsoft.com/windows/desktop/Rpc/rpc-return-values
# https://msdn.microsoft.com/library/default.asp?url=/library/en-us/randz/protocol/common_return_values.asp
# winerror.h
# https://www.opengroup.org/onlinepubs/9629399/apdxn.htm

rpc_status_codes = {
    0x00000005: "rpc_s_access_denied",
    0x00000008: "Authentication type not recognized",
    0x000006D8: "rpc_fault_cant_perform",
    0x000006C6: "rpc_x_invalid_bound",  # the arrays bound are invalid
    0x000006E4: "rpc_s_cannot_support: The requested operation is not supported.",  # some operation is not supported
    0x000006F7: "rpc_x_bad_stub_data",  # the stub data is invalid, doesn't match with the IDL definition
    0x1C010001: "nca_s_comm_failure",  # unable to get response from server:
    0x1C010002: "nca_s_op_rng_error",  # bad operation number in call
    0x1C010003: "nca_s_unk_if",  # unknown interface
    0x1C010006: "nca_s_wrong_boot_time",  # client passed server wrong server boot time
    0x1C010009: "nca_s_you_crashed",  # a restarted server called back a client
    0x1C01000B: "nca_s_proto_error",  # someone messed up the protocol
    0x1C010013: "nca_s_out_args_too_big ",  # output args too big
    0x1C010014: "nca_s_server_too_busy",  # server is too busy to handle call
    0x1C010015: "nca_s_fault_string_too_long",  # string argument longer than declared max len
    0x1C010017: "nca_s_unsupported_type ",  # no implementation of generic operation for object
    0x1C000001: "nca_s_fault_int_div_by_zero",
    0x1C000002: "nca_s_fault_addr_error ",
    0x1C000003: "nca_s_fault_fp_div_zero",
    0x1C000004: "nca_s_fault_fp_underflow",
    0x1C000005: "nca_s_fault_fp_overflow",
    0x1C000006: "nca_s_fault_invalid_tag",
    0x1C000007: "nca_s_fault_invalid_bound ",
    0x1C000008: "nca_s_rpc_version_mismatch",
    0x1C000009: "nca_s_unspec_reject ",
    0x1C00000A: "nca_s_bad_actid",
    0x1C00000B: "nca_s_who_are_you_failed",
    0x1C00000C: "nca_s_manager_not_entered ",
    0x1C00000D: "nca_s_fault_cancel",
    0x1C00000E: "nca_s_fault_ill_inst",
    0x1C00000F: "nca_s_fault_fp_error",
    0x1C000010: "nca_s_fault_int_overflow",
    0x1C000012: "nca_s_fault_unspec",
    0x1C000013: "nca_s_fault_remote_comm_failure ",
    0x1C000014: "nca_s_fault_pipe_empty ",
    0x1C000015: "nca_s_fault_pipe_closed",
    0x1C000016: "nca_s_fault_pipe_order ",
    0x1C000017: "nca_s_fault_pipe_discipline",
    0x1C000018: "nca_s_fault_pipe_comm_error",
    0x1C000019: "nca_s_fault_pipe_memory",
    0x1C00001A: "nca_s_fault_context_mismatch ",
    0x1C00001B: "nca_s_fault_remote_no_memory ",
    0x1C00001C: "nca_s_invalid_pres_context_id",
    0x1C00001D: "nca_s_unsupported_authn_level",
    0x1C00001F: "nca_s_invalid_checksum ",
    0x1C000020: "nca_s_invalid_crc",
    0x1C000021: "nca_s_fault_user_defined",
    0x1C000022: "nca_s_fault_tx_open_failed",
    0x1C000023: "nca_s_fault_codeset_conv_error",
    0x1C000024: "nca_s_fault_object_not_found ",
    0x1C000025: "nca_s_fault_no_client_stub",
    0x16C9A000: "rpc_s_mod",
    0x16C9A001: "rpc_s_op_rng_error",
    0x16C9A002: "rpc_s_cant_create_socket",
    0x16C9A003: "rpc_s_cant_bind_socket",
    0x16C9A004: "rpc_s_not_in_call",
    0x16C9A005: "rpc_s_no_port",
    0x16C9A006: "rpc_s_wrong_boot_time",
    0x16C9A007: "rpc_s_too_many_sockets",
    0x16C9A008: "rpc_s_illegal_register",
    0x16C9A009: "rpc_s_cant_recv",
    0x16C9A00A: "rpc_s_bad_pkt",
    0x16C9A00B: "rpc_s_unbound_handle",
    0x16C9A00C: "rpc_s_addr_in_use",
    0x16C9A00D: "rpc_s_in_args_too_big",
    0x16C9A00E: "rpc_s_string_too_long",
    0x16C9A00F: "rpc_s_too_many_objects",
    0x16C9A010: "rpc_s_binding_has_no_auth",
    0x16C9A011: "rpc_s_unknown_authn_service",
    0x16C9A012: "rpc_s_no_memory",
    0x16C9A013: "rpc_s_cant_nmalloc",
    0x16C9A014: "rpc_s_call_faulted",
    0x16C9A015: "rpc_s_call_failed",
    0x16C9A016: "rpc_s_comm_failure",
    0x16C9A017: "rpc_s_rpcd_comm_failure",
    0x16C9A018: "rpc_s_illegal_family_rebind",
    0x16C9A019: "rpc_s_invalid_handle",
    0x16C9A01A: "rpc_s_coding_error",
    0x16C9A01B: "rpc_s_object_not_found",
    0x16C9A01C: "rpc_s_cthread_not_found",
    0x16C9A01D: "rpc_s_invalid_binding",
    0x16C9A01E: "rpc_s_already_registered",
    0x16C9A01F: "rpc_s_endpoint_not_found",
    0x16C9A020: "rpc_s_invalid_rpc_protseq",
    0x16C9A021: "rpc_s_desc_not_registered",
    0x16C9A022: "rpc_s_already_listening",
    0x16C9A023: "rpc_s_no_protseqs",
    0x16C9A024: "rpc_s_no_protseqs_registered",
    0x16C9A025: "rpc_s_no_bindings",
    0x16C9A026: "rpc_s_max_descs_exceeded",
    0x16C9A027: "rpc_s_no_interfaces",
    0x16C9A028: "rpc_s_invalid_timeout",
    0x16C9A029: "rpc_s_cant_inq_socket",
    0x16C9A02A: "rpc_s_invalid_naf_id",
    0x16C9A02B: "rpc_s_inval_net_addr",
    0x16C9A02C: "rpc_s_unknown_if",
    0x16C9A02D: "rpc_s_unsupported_type",
    0x16C9A02E: "rpc_s_invalid_call_opt",
    0x16C9A02F: "rpc_s_no_fault",
    0x16C9A030: "rpc_s_cancel_timeout",
    0x16C9A031: "rpc_s_call_cancelled",
    0x16C9A032: "rpc_s_invalid_call_handle",
    0x16C9A033: "rpc_s_cannot_alloc_assoc",
    0x16C9A034: "rpc_s_cannot_connect",
    0x16C9A035: "rpc_s_connection_aborted",
    0x16C9A036: "rpc_s_connection_closed",
    0x16C9A037: "rpc_s_cannot_accept",
    0x16C9A038: "rpc_s_assoc_grp_not_found",
    0x16C9A039: "rpc_s_stub_interface_error",
    0x16C9A03A: "rpc_s_invalid_object",
    0x16C9A03B: "rpc_s_invalid_type",
    0x16C9A03C: "rpc_s_invalid_if_opnum",
    0x16C9A03D: "rpc_s_different_server_instance",
    0x16C9A03E: "rpc_s_protocol_error",
    0x16C9A03F: "rpc_s_cant_recvmsg",
    0x16C9A040: "rpc_s_invalid_string_binding",
    0x16C9A041: "rpc_s_connect_timed_out",
    0x16C9A042: "rpc_s_connect_rejected",
    0x16C9A043: "rpc_s_network_unreachable",
    0x16C9A044: "rpc_s_connect_no_resources",
    0x16C9A045: "rpc_s_rem_network_shutdown",
    0x16C9A046: "rpc_s_too_many_rem_connects",
    0x16C9A047: "rpc_s_no_rem_endpoint",
    0x16C9A048: "rpc_s_rem_host_down",
    0x16C9A049: "rpc_s_host_unreachable",
    0x16C9A04A: "rpc_s_access_control_info_inv",
    0x16C9A04B: "rpc_s_loc_connect_aborted",
    0x16C9A04C: "rpc_s_connect_closed_by_rem",
    0x16C9A04D: "rpc_s_rem_host_crashed",
    0x16C9A04E: "rpc_s_invalid_endpoint_format",
    0x16C9A04F: "rpc_s_unknown_status_code",
    0x16C9A050: "rpc_s_unknown_mgr_type",
    0x16C9A051: "rpc_s_assoc_creation_failed",
    0x16C9A052: "rpc_s_assoc_grp_max_exceeded",
    0x16C9A053: "rpc_s_assoc_grp_alloc_failed",
    0x16C9A054: "rpc_s_sm_invalid_state",
    0x16C9A055: "rpc_s_assoc_req_rejected",
    0x16C9A056: "rpc_s_assoc_shutdown",
    0x16C9A057: "rpc_s_tsyntaxes_unsupported",
    0x16C9A058: "rpc_s_context_id_not_found",
    0x16C9A059: "rpc_s_cant_listen_socket",
    0x16C9A05A: "rpc_s_no_addrs",
    0x16C9A05B: "rpc_s_cant_getpeername",
    0x16C9A05C: "rpc_s_cant_get_if_id",
    0x16C9A05D: "rpc_s_protseq_not_supported",
    0x16C9A05E: "rpc_s_call_orphaned",
    0x16C9A05F: "rpc_s_who_are_you_failed",
    0x16C9A060: "rpc_s_unknown_reject",
    0x16C9A061: "rpc_s_type_already_registered",
    0x16C9A062: "rpc_s_stop_listening_disabled",
    0x16C9A063: "rpc_s_invalid_arg",
    0x16C9A064: "rpc_s_not_supported",
    0x16C9A065: "rpc_s_wrong_kind_of_binding",
    0x16C9A066: "rpc_s_authn_authz_mismatch",
    0x16C9A067: "rpc_s_call_queued",
    0x16C9A068: "rpc_s_cannot_set_nodelay",
    0x16C9A069: "rpc_s_not_rpc_tower",
    0x16C9A06A: "rpc_s_invalid_rpc_protid",
    0x16C9A06B: "rpc_s_invalid_rpc_floor",
    0x16C9A06C: "rpc_s_call_timeout",
    0x16C9A06D: "rpc_s_mgmt_op_disallowed",
    0x16C9A06E: "rpc_s_manager_not_entered",
    0x16C9A06F: "rpc_s_calls_too_large_for_wk_ep",
    0x16C9A070: "rpc_s_server_too_busy",
    0x16C9A071: "rpc_s_prot_version_mismatch",
    0x16C9A072: "rpc_s_rpc_prot_version_mismatch",
    0x16C9A073: "rpc_s_ss_no_import_cursor",
    0x16C9A074: "rpc_s_fault_addr_error",
    0x16C9A075: "rpc_s_fault_context_mismatch",
    0x16C9A076: "rpc_s_fault_fp_div_by_zero",
    0x16C9A077: "rpc_s_fault_fp_error",
    0x16C9A078: "rpc_s_fault_fp_overflow",
    0x16C9A079: "rpc_s_fault_fp_underflow",
    0x16C9A07A: "rpc_s_fault_ill_inst",
    0x16C9A07B: "rpc_s_fault_int_div_by_zero",
    0x16C9A07C: "rpc_s_fault_int_overflow",
    0x16C9A07D: "rpc_s_fault_invalid_bound",
    0x16C9A07E: "rpc_s_fault_invalid_tag",
    0x16C9A07F: "rpc_s_fault_pipe_closed",
    0x16C9A080: "rpc_s_fault_pipe_comm_error",
    0x16C9A081: "rpc_s_fault_pipe_discipline",
    0x16C9A082: "rpc_s_fault_pipe_empty",
    0x16C9A083: "rpc_s_fault_pipe_memory",
    0x16C9A084: "rpc_s_fault_pipe_order",
    0x16C9A085: "rpc_s_fault_remote_comm_failure",
    0x16C9A086: "rpc_s_fault_remote_no_memory",
    0x16C9A087: "rpc_s_fault_unspec",
    0x16C9A088: "uuid_s_bad_version",
    0x16C9A089: "uuid_s_socket_failure",
    0x16C9A08A: "uuid_s_getconf_failure",
    0x16C9A08B: "uuid_s_no_address",
    0x16C9A08C: "uuid_s_overrun",
    0x16C9A08D: "uuid_s_internal_error",
    0x16C9A08E: "uuid_s_coding_error",
    0x16C9A08F: "uuid_s_invalid_string_uuid",
    0x16C9A090: "uuid_s_no_memory",
    0x16C9A091: "rpc_s_no_more_entries",
    0x16C9A092: "rpc_s_unknown_ns_error",
    0x16C9A093: "rpc_s_name_service_unavailable",
    0x16C9A094: "rpc_s_incomplete_name",
    0x16C9A095: "rpc_s_group_not_found",
    0x16C9A096: "rpc_s_invalid_name_syntax",
    0x16C9A097: "rpc_s_no_more_members",
    0x16C9A098: "rpc_s_no_more_interfaces",
    0x16C9A099: "rpc_s_invalid_name_service",
    0x16C9A09A: "rpc_s_no_name_mapping",
    0x16C9A09B: "rpc_s_profile_not_found",
    0x16C9A09C: "rpc_s_not_found",
    0x16C9A09D: "rpc_s_no_updates",
    0x16C9A09E: "rpc_s_update_failed",
    0x16C9A09F: "rpc_s_no_match_exported",
    0x16C9A0A0: "rpc_s_entry_not_found",
    0x16C9A0A1: "rpc_s_invalid_inquiry_context",
    0x16C9A0A2: "rpc_s_interface_not_found",
    0x16C9A0A3: "rpc_s_group_member_not_found",
    0x16C9A0A4: "rpc_s_entry_already_exists",
    0x16C9A0A5: "rpc_s_nsinit_failure",
    0x16C9A0A6: "rpc_s_unsupported_name_syntax",
    0x16C9A0A7: "rpc_s_no_more_elements",
    0x16C9A0A8: "rpc_s_no_ns_permission",
    0x16C9A0A9: "rpc_s_invalid_inquiry_type",
    0x16C9A0AA: "rpc_s_profile_element_not_found",
    0x16C9A0AB: "rpc_s_profile_element_replaced",
    0x16C9A0AC: "rpc_s_import_already_done",
    0x16C9A0AD: "rpc_s_database_busy",
    0x16C9A0AE: "rpc_s_invalid_import_context",
    0x16C9A0AF: "rpc_s_uuid_set_not_found",
    0x16C9A0B0: "rpc_s_uuid_member_not_found",
    0x16C9A0B1: "rpc_s_no_interfaces_exported",
    0x16C9A0B2: "rpc_s_tower_set_not_found",
    0x16C9A0B3: "rpc_s_tower_member_not_found",
    0x16C9A0B4: "rpc_s_obj_uuid_not_found",
    0x16C9A0B5: "rpc_s_no_more_bindings",
    0x16C9A0B6: "rpc_s_invalid_priority",
    0x16C9A0B7: "rpc_s_not_rpc_entry",
    0x16C9A0B8: "rpc_s_invalid_lookup_context",
    0x16C9A0B9: "rpc_s_binding_vector_full",
    0x16C9A0BA: "rpc_s_cycle_detected",
    0x16C9A0BB: "rpc_s_nothing_to_export",
    0x16C9A0BC: "rpc_s_nothing_to_unexport",
    0x16C9A0BD: "rpc_s_invalid_vers_option",
    0x16C9A0BE: "rpc_s_no_rpc_data",
    0x16C9A0BF: "rpc_s_mbr_picked",
    0x16C9A0C0: "rpc_s_not_all_objs_unexported",
    0x16C9A0C1: "rpc_s_no_entry_name",
    0x16C9A0C2: "rpc_s_priority_group_done",
    0x16C9A0C3: "rpc_s_partial_results",
    0x16C9A0C4: "rpc_s_no_env_setup",
    0x16C9A0C5: "twr_s_unknown_sa",
    0x16C9A0C6: "twr_s_unknown_tower",
    0x16C9A0C7: "twr_s_not_implemented",
    0x16C9A0C8: "rpc_s_max_calls_too_small",
    0x16C9A0C9: "rpc_s_cthread_create_failed",
    0x16C9A0CA: "rpc_s_cthread_pool_exists",
    0x16C9A0CB: "rpc_s_cthread_no_such_pool",
    0x16C9A0CC: "rpc_s_cthread_invoke_disabled",
    0x16C9A0CD: "ept_s_cant_perform_op",
    0x16C9A0CE: "ept_s_no_memory",
    0x16C9A0CF: "ept_s_database_invalid",
    0x16C9A0D0: "ept_s_cant_create",
    0x16C9A0D1: "ept_s_cant_access",
    0x16C9A0D2: "ept_s_database_already_open",
    0x16C9A0D3: "ept_s_invalid_entry",
    0x16C9A0D4: "ept_s_update_failed",
    0x16C9A0D5: "ept_s_invalid_context",
    0x16C9A0D6: "ept_s_not_registered",
    0x16C9A0D7: "ept_s_server_unavailable",
    0x16C9A0D8: "rpc_s_underspecified_name",
    0x16C9A0D9: "rpc_s_invalid_ns_handle",
    0x16C9A0DA: "rpc_s_unknown_error",
    0x16C9A0DB: "rpc_s_ss_char_trans_open_fail",
    0x16C9A0DC: "rpc_s_ss_char_trans_short_file",
    0x16C9A0DD: "rpc_s_ss_context_damaged",
    0x16C9A0DE: "rpc_s_ss_in_null_context",
    0x16C9A0DF: "rpc_s_socket_failure",
    0x16C9A0E0: "rpc_s_unsupported_protect_level",
    0x16C9A0E1: "rpc_s_invalid_checksum",
    0x16C9A0E2: "rpc_s_invalid_credentials",
    0x16C9A0E3: "rpc_s_credentials_too_large",
    0x16C9A0E4: "rpc_s_call_id_not_found",
    0x16C9A0E5: "rpc_s_key_id_not_found",
    0x16C9A0E6: "rpc_s_auth_bad_integrity",
    0x16C9A0E7: "rpc_s_auth_tkt_expired",
    0x16C9A0E8: "rpc_s_auth_tkt_nyv",
    0x16C9A0E9: "rpc_s_auth_repeat",
    0x16C9A0EA: "rpc_s_auth_not_us",
    0x16C9A0EB: "rpc_s_auth_badmatch",
    0x16C9A0EC: "rpc_s_auth_skew",
    0x16C9A0ED: "rpc_s_auth_badaddr",
    0x16C9A0EE: "rpc_s_auth_badversion",
    0x16C9A0EF: "rpc_s_auth_msg_type",
    0x16C9A0F0: "rpc_s_auth_modified",
    0x16C9A0F1: "rpc_s_auth_badorder",
    0x16C9A0F2: "rpc_s_auth_badkeyver",
    0x16C9A0F3: "rpc_s_auth_nokey",
    0x16C9A0F4: "rpc_s_auth_mut_fail",
    0x16C9A0F5: "rpc_s_auth_baddirection",
    0x16C9A0F6: "rpc_s_auth_method",
    0x16C9A0F7: "rpc_s_auth_badseq",
    0x16C9A0F8: "rpc_s_auth_inapp_cksum",
    0x16C9A0F9: "rpc_s_auth_field_toolong",
    0x16C9A0FA: "rpc_s_invalid_crc",
    0x16C9A0FB: "rpc_s_binding_incomplete",
    0x16C9A0FC: "rpc_s_key_func_not_allowed",
    0x16C9A0FD: "rpc_s_unknown_stub_rtl_if_vers",
    0x16C9A0FE: "rpc_s_unknown_ifspec_vers",
    0x16C9A0FF: "rpc_s_proto_unsupp_by_auth",
    0x16C9A100: "rpc_s_authn_challenge_malformed",
    0x16C9A101: "rpc_s_protect_level_mismatch",
    0x16C9A102: "rpc_s_no_mepv",
    0x16C9A103: "rpc_s_stub_protocol_error",
    0x16C9A104: "rpc_s_class_version_mismatch",
    0x16C9A105: "rpc_s_helper_not_running",
    0x16C9A106: "rpc_s_helper_short_read",
    0x16C9A107: "rpc_s_helper_catatonic",
    0x16C9A108: "rpc_s_helper_aborted",
    0x16C9A109: "rpc_s_not_in_kernel",
    0x16C9A10A: "rpc_s_helper_wrong_user",
    0x16C9A10B: "rpc_s_helper_overflow",
    0x16C9A10C: "rpc_s_dg_need_way_auth",
    0x16C9A10D: "rpc_s_unsupported_auth_subtype",
    0x16C9A10E: "rpc_s_wrong_pickle_type",
    0x16C9A10F: "rpc_s_not_listening",
    0x16C9A110: "rpc_s_ss_bad_buffer",
    0x16C9A111: "rpc_s_ss_bad_es_action",
    0x16C9A112: "rpc_s_ss_wrong_es_version",
    0x16C9A113: "rpc_s_fault_user_defined",
    0x16C9A114: "rpc_s_ss_incompatible_codesets",
    0x16C9A115: "rpc_s_tx_not_in_transaction",
    0x16C9A116: "rpc_s_tx_open_failed",
    0x16C9A117: "rpc_s_partial_credentials",
    0x16C9A118: "rpc_s_ss_invalid_codeset_tag",
    0x16C9A119: "rpc_s_mgmt_bad_type",
    0x16C9A11A: "rpc_s_ss_invalid_char_input",
    0x16C9A11B: "rpc_s_ss_short_conv_buffer",
    0x16C9A11C: "rpc_s_ss_iconv_error",
    0x16C9A11D: "rpc_s_ss_no_compat_codeset",
    0x16C9A11E: "rpc_s_ss_no_compat_charsets",
    0x16C9A11F: "dce_cs_c_ok",
    0x16C9A120: "dce_cs_c_unknown",
    0x16C9A121: "dce_cs_c_notfound",
    0x16C9A122: "dce_cs_c_cannot_open_file",
    0x16C9A123: "dce_cs_c_cannot_read_file",
    0x16C9A124: "dce_cs_c_cannot_allocate_memory",
    0x16C9A125: "rpc_s_ss_cleanup_failed",
    0x16C9A126: "rpc_svc_desc_general",
    0x16C9A127: "rpc_svc_desc_mutex",
    0x16C9A128: "rpc_svc_desc_xmit",
    0x16C9A129: "rpc_svc_desc_recv",
    0x16C9A12A: "rpc_svc_desc_dg_state",
    0x16C9A12B: "rpc_svc_desc_cancel",
    0x16C9A12C: "rpc_svc_desc_orphan",
    0x16C9A12D: "rpc_svc_desc_cn_state",
    0x16C9A12E: "rpc_svc_desc_cn_pkt",
    0x16C9A12F: "rpc_svc_desc_pkt_quotas",
    0x16C9A130: "rpc_svc_desc_auth",
    0x16C9A131: "rpc_svc_desc_source",
    0x16C9A132: "rpc_svc_desc_stats",
    0x16C9A133: "rpc_svc_desc_mem",
    0x16C9A134: "rpc_svc_desc_mem_type",
    0x16C9A135: "rpc_svc_desc_dg_pktlog",
    0x16C9A136: "rpc_svc_desc_thread_id",
    0x16C9A137: "rpc_svc_desc_timestamp",
    0x16C9A138: "rpc_svc_desc_cn_errors",
    0x16C9A139: "rpc_svc_desc_conv_thread",
    0x16C9A13A: "rpc_svc_desc_pid",
    0x16C9A13B: "rpc_svc_desc_atfork",
    0x16C9A13C: "rpc_svc_desc_cma_thread",
    0x16C9A13D: "rpc_svc_desc_inherit",
    0x16C9A13E: "rpc_svc_desc_dg_sockets",
    0x16C9A13F: "rpc_svc_desc_timer",
    0x16C9A140: "rpc_svc_desc_threads",
    0x16C9A141: "rpc_svc_desc_server_call",
    0x16C9A142: "rpc_svc_desc_nsi",
    0x16C9A143: "rpc_svc_desc_dg_pkt",
    0x16C9A144: "rpc_m_cn_ill_state_trans_sa",
    0x16C9A145: "rpc_m_cn_ill_state_trans_ca",
    0x16C9A146: "rpc_m_cn_ill_state_trans_sg",
    0x16C9A147: "rpc_m_cn_ill_state_trans_cg",
    0x16C9A148: "rpc_m_cn_ill_state_trans_sr",
    0x16C9A149: "rpc_m_cn_ill_state_trans_cr",
    0x16C9A14A: "rpc_m_bad_pkt_type",
    0x16C9A14B: "rpc_m_prot_mismatch",
    0x16C9A14C: "rpc_m_frag_toobig",
    0x16C9A14D: "rpc_m_unsupp_stub_rtl_if",
    0x16C9A14E: "rpc_m_unhandled_callstate",
    0x16C9A14F: "rpc_m_call_failed",
    0x16C9A150: "rpc_m_call_failed_no_status",
    0x16C9A151: "rpc_m_call_failed_errno",
    0x16C9A152: "rpc_m_call_failed_s",
    0x16C9A153: "rpc_m_call_failed_c",
    0x16C9A154: "rpc_m_errmsg_toobig",
    0x16C9A155: "rpc_m_invalid_srchattr",
    0x16C9A156: "rpc_m_nts_not_found",
    0x16C9A157: "rpc_m_invalid_accbytcnt",
    0x16C9A158: "rpc_m_pre_v2_ifspec",
    0x16C9A159: "rpc_m_unk_ifspec",
    0x16C9A15A: "rpc_m_recvbuf_toosmall",
    0x16C9A15B: "rpc_m_unalign_authtrl",
    0x16C9A15C: "rpc_m_unexpected_exc",
    0x16C9A15D: "rpc_m_no_stub_data",
    0x16C9A15E: "rpc_m_eventlist_full",
    0x16C9A15F: "rpc_m_unk_sock_type",
    0x16C9A160: "rpc_m_unimp_call",
    0x16C9A161: "rpc_m_invalid_seqnum",
    0x16C9A162: "rpc_m_cant_create_uuid",
    0x16C9A163: "rpc_m_pre_v2_ss",
    0x16C9A164: "rpc_m_dgpkt_pool_corrupt",
    0x16C9A165: "rpc_m_dgpkt_bad_free",
    0x16C9A166: "rpc_m_lookaside_corrupt",
    0x16C9A167: "rpc_m_alloc_fail",
    0x16C9A168: "rpc_m_realloc_fail",
    0x16C9A169: "rpc_m_cant_open_file",
    0x16C9A16A: "rpc_m_cant_read_addr",
    0x16C9A16B: "rpc_svc_desc_libidl",
    0x16C9A16C: "rpc_m_ctxrundown_nomem",
    0x16C9A16D: "rpc_m_ctxrundown_exc",
    0x16C9A16E: "rpc_s_fault_codeset_conv_error",
    0x16C9A16F: "rpc_s_no_call_active",
    0x16C9A170: "rpc_s_cannot_support",
    0x16C9A171: "rpc_s_no_context_available",
}


class DCERPCException(Exception):
    """
    This is the exception every client should catch regardless of the underlying
    DCERPC Transport used.
    """

    def __init__(self, error_string=None, error_code=None, packet=None):
        """
        :param string error_string: A string you want to show explaining the exception. Otherwise the default ones will be used
        :param integer error_code: the error_code if we're using a dictionary with error's descriptions
        :param NDR packet: if successfully decoded, the NDR packet of the response call. This could probably have useful
        information
        """
        Exception.__init__(self)
        self.packet = packet
        self.error_string = error_string
        if packet is not None:
            try:
                self.error_code = packet["ErrorCode"]
            except:
                self.error_code = error_code
        else:
            self.error_code = error_code

    def get_error_code(self):
        return self.error_code

    def get_packet(self):
        return self.packet

    def __str__(self):
        key = self.error_code
        if self.error_string is not None:
            return self.error_string
        if key in rpc_status_codes:
            error_msg_short = rpc_status_codes[key]
            return "DCERPC Runtime Error: code: 0x%x - %s " % (
                self.error_code,
                error_msg_short,
            )
        else:
            return "DCERPC Runtime Error: unknown error code: 0x%x" % self.error_code


# Context Item
class CtxItem(Structure):
    structure = (
        ("ContextID", "<H=0"),
        ("TransItems", "B=0"),
        ("Pad", "B=0"),
        ("AbstractSyntax", '20s=""'),
        ("TransferSyntax", '20s=""'),
    )


class CtxItemResult(Structure):
    structure = (
        ("Result", "<H=0"),
        ("Reason", "<H=0"),
        ("TransferSyntax", '20s=""'),
    )


class SEC_TRAILER(Structure):
    commonHdr = (
        ("auth_type", "B=10"),
        ("auth_level", "B=0"),
        ("auth_pad_len", "B=0"),
        ("auth_rsvrd", "B=0"),
        ("auth_ctx_id", "<L=747920"),
    )


class MSRPCHeader(Structure):
    _SIZE = 16
    commonHdr = (
        ("ver_major", "B=5"),  # 0
        ("ver_minor", "B=0"),  # 1
        ("type", "B=0"),  # 2
        ("flags", "B=0"),  # 3
        ("representation", "<L=0x10"),  # 4
        (
            "frag_len",
            '<H=self._SIZE+len(auth_data)+(16 if (self["flags"] & 0x80) > 0 else 0)+len(pduData)+len(pad)+len(sec_trailer)',
        ),  # 8
        ("auth_len", "<H=len(auth_data)"),  # 10
        ("call_id", "<L=1"),  # 12    <-- Common up to here (including this)
    )

    structure = (
        (
            "dataLen",
            "_-pduData",
            'self["frag_len"]-self["auth_len"]-self._SIZE-(8 if self["auth_len"] > 0 else 0)',
        ),
        ("pduData", ":"),
        (
            "_pad",
            "_-pad",
            '(4 - ((self._SIZE + (16 if (self["flags"] & 0x80) > 0 else 0) + len(self["pduData"])) & 3) & 3)',
        ),
        ("pad", ":"),
        ("_sec_trailer", "_-sec_trailer", '8 if self["auth_len"] > 0 else 0'),
        ("sec_trailer", ":"),
        ("auth_dataLen", "_-auth_data", 'self["auth_len"]'),
        ("auth_data", ":"),
    )

    def __init__(self, data=None, alignment=0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self["ver_major"] = 5
            self["ver_minor"] = 0
            self["flags"] = PFC_FIRST_FRAG | PFC_LAST_FRAG
            self["type"] = MSRPC_REQUEST
            self.__frag_len_set = 0
            self["auth_len"] = 0
            self["pduData"] = b""
            self["auth_data"] = b""
            self["sec_trailer"] = b""
            self["pad"] = b""

    def get_header_size(self):
        return self._SIZE + (16 if (self["flags"] & PFC_OBJECT_UUID) > 0 else 0)

    def get_packet(self):
        if self["auth_data"] != b"":
            self["auth_len"] = len(self["auth_data"])
        # The sec_trailer structure MUST be 4-byte aligned with respect to
        # the beginning of the PDU. Padding octets MUST be used to align the
        # sec_trailer structure if its natural beginning is not already 4-byte aligned
        ##self['pad'] = '\xAA' * (4 - ((self._SIZE + len(self['pduData'])) & 3) & 3)

        return self.getData()


class MSRPCRequestHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + (
        ("alloc_hint", "<L=0"),  # 16
        ("ctx_id", "<H=0"),  # 20
        ("op_num", "<H=0"),  # 22
        ("_uuid", "_-uuid", '16 if self["flags"] & 0x80 > 0 else 0'),  # 22
        ("uuid", ":"),  # 22
    )

    def __init__(self, data=None, alignment=0):
        MSRPCHeader.__init__(self, data, alignment)
        if data is None:
            self["type"] = MSRPC_REQUEST
            self["ctx_id"] = 0
            self["uuid"] = b""


class MSRPCRespHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + (
        ("alloc_hint", "<L=0"),  # 16
        ("ctx_id", "<H=0"),  # 20
        ("cancel_count", "<B=0"),  # 22
        ("padding", "<B=0"),  # 23
    )

    def __init__(self, aBuffer=None, alignment=0):
        MSRPCHeader.__init__(self, aBuffer, alignment)
        if aBuffer is None:
            self["type"] = MSRPC_RESPONSE
            self["ctx_id"] = 0


class MSRPCBind(Structure):
    _CTX_ITEM_LEN = len(CtxItem())
    structure = (
        ("max_tfrag", "<H=4280"),
        ("max_rfrag", "<H=4280"),
        ("assoc_group", "<L=0"),
        ("ctx_num", "B=0"),
        ("Reserved", "B=0"),
        ("Reserved2", "<H=0"),
        ("_ctx_items", "_-ctx_items", 'self["ctx_num"]*self._CTX_ITEM_LEN'),
        ("ctx_items", ":"),
    )

    def __init__(self, data=None, alignment=0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self["max_tfrag"] = 4280
            self["max_rfrag"] = 4280
            self["assoc_group"] = 0
            self["ctx_num"] = 1
            self["ctx_items"] = b""
        self.__ctx_items = []

    def addCtxItem(self, item):
        self.__ctx_items.append(item)

    def getData(self):
        self["ctx_num"] = len(self.__ctx_items)
        for i in self.__ctx_items:
            self["ctx_items"] += i.getData()
        return Structure.getData(self)


class MSRPCBindAck(MSRPCHeader):
    _SIZE = 26  # Up to SecondaryAddr
    _CTX_ITEM_LEN = len(CtxItemResult())
    structure = (
        ("max_tfrag", "<H=0"),
        ("max_rfrag", "<H=0"),
        ("assoc_group", "<L=0"),
        ("SecondaryAddrLen", "<H&SecondaryAddr"),
        ("SecondaryAddr", "z"),  # Optional if SecondaryAddrLen == 0
        ("PadLen", "_-Pad", '(4-((self["SecondaryAddrLen"]+self._SIZE) % 4))%4'),
        ("Pad", ":"),
        ("ctx_num", "B=0"),
        ("Reserved", "B=0"),
        ("Reserved2", "<H=0"),
        ("_ctx_items", "_-ctx_items", 'self["ctx_num"]*self._CTX_ITEM_LEN'),
        ("ctx_items", ":"),
        ("_sec_trailer", "_-sec_trailer", '8 if self["auth_len"] > 0 else 0'),
        ("sec_trailer", ":"),
        ("auth_dataLen", "_-auth_data", 'self["auth_len"]'),
        ("auth_data", ":"),
    )

    def __init__(self, data=None, alignment=0):
        self.__ctx_items = []
        MSRPCHeader.__init__(self, data, alignment)
        if data is None:
            self["Pad"] = b""
            self["ctx_items"] = b""
            self["sec_trailer"] = b""
            self["auth_data"] = b""

    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self, index):
        return self.__ctx_items[index - 1]

    def fromString(self, data):
        Structure.fromString(self, data)
        # Parse the ctx_items
        data = self["ctx_items"]
        for i in range(self["ctx_num"]):
            item = CtxItemResult(data)
            self.__ctx_items.append(item)
            data = data[len(item) :]


class MSRPCBindNak(Structure):
    structure = (
        ("RejectedReason", "<H=0"),
        ("SupportedVersions", ":"),
    )

    def __init__(self, data=None, alignment=0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self["SupportedVersions"] = b""


class DCERPC:
    # Standard NDR Representation
    NDRSyntax = uuidtup_to_bin(("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0"))
    # NDR 64
    NDR64Syntax = uuidtup_to_bin(("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0"))
    transfer_syntax = NDRSyntax

    def __init__(self, transport):
        self._transport = transport
        self.set_ctx_id(0)
        self._max_user_frag = None
        self.set_default_max_fragment_size()
        self._ctx = None

    def get_rpc_transport(self):
        return self._transport

    def set_ctx_id(self, ctx_id):
        self._ctx = ctx_id

    def connect(self):
        return self._transport.connect()

    def disconnect(self):
        return self._transport.disconnect()

    def set_max_fragment_size(self, fragment_size):
        # -1 is default fragment size: 0 for v5, 1300 y pico for v4
        #  0 is don't fragment
        #    other values are max fragment size
        if fragment_size == -1:
            self.set_default_max_fragment_size()
        else:
            self._max_user_frag = fragment_size

    def set_default_max_fragment_size(self):
        # default is 0: don'fragment. v4 will override this method
        self._max_user_frag = 0

    def send(self, data):
        raise RuntimeError("virtual method. Not implemented in subclass")

    def recv(self):
        raise RuntimeError("virtual method. Not implemented in subclass")

    def alter_ctx(self, newUID, bogus_binds=""):
        raise RuntimeError("virtual method. Not implemented in subclass")

    def set_credentials(
        self,
        username,
        password,
        domain="",
        lmhash="",
        nthash="",
        aesKey="",
        TGT=None,
        TGS=None,
    ):
        pass

    def set_auth_level(self, auth_level):
        pass

    def set_auth_type(self, auth_type, callback=None):
        pass

    def get_idempotent(self):
        return 0

    def set_idempotent(self, flag):
        pass

    def call(self, function, body, uuid=None):
        if hasattr(body, "getData"):
            return self.send(DCERPC_RawCall(function, body.getData(), uuid))
        else:
            return self.send(DCERPC_RawCall(function, body, uuid))

    def request(self, request, uuid=None, checkError=True):
        if self.transfer_syntax == self.NDR64Syntax:
            request.changeTransferSyntax(self.NDR64Syntax)
            isNDR64 = True
        else:
            isNDR64 = False

        self.call(request.opnum, request, uuid)
        answer = self.recv()

        __import__(request.__module__)
        module = sys.modules[request.__module__]
        respClass = getattr(module, request.__class__.__name__ + "Response")

        if answer[-4:] != b"\x00\x00\x00\x00" and checkError is True:
            error_code = unpack("<L", answer[-4:])[0]
            if error_code in rpc_status_codes:
                # This is an error we can handle
                exception = DCERPCException(error_code=error_code)
            else:
                sessionErrorClass = getattr(module, "DCERPCSessionError")
                try:
                    # Try to unpack the answer, even if it is an error, it works most of the times
                    response = respClass(answer, isNDR64=isNDR64)
                except:
                    # No luck :(
                    exception = sessionErrorClass(error_code=error_code)
                else:
                    exception = sessionErrorClass(
                        packet=response, error_code=error_code
                    )
            raise exception
        else:
            response = respClass(answer, isNDR64=isNDR64)
            return response


class DCERPC_v4(DCERPC):
    pass


class DCERPC_v5(DCERPC):
    def __init__(self, transport):
        DCERPC.__init__(self, transport)
        self.__auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.__auth_type = RPC_C_AUTHN_WINNT
        self.__auth_type_callback = None
        # Flags of the authenticated session. We will need them throughout the connection
        self.__auth_flags = 0
        self.__username = None
        self.__password = None
        self.__domain = ""
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = ""
        self.__TGT = None
        self.__TGS = None

        self.__clientSigningKey = b""
        self.__serverSigningKey = b""
        self.__clientSealingKey = b""
        self.__clientSealingHandle = b""
        self.__serverSealingKey = b""
        self.__serverSealingHandle = b""
        self.__sequence = 0

        self.transfer_syntax = uuidtup_to_bin(
            ("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
        )
        self.__callid = 1
        self._ctx = 0
        self.__sessionKey = None
        self.__max_xmit_size = 0
        self.__flags = 0
        self.__cipher = None
        self.__confounder = b""
        self.__gss = None

    def set_session_key(self, session_key):
        self.__sessionKey = session_key

    def get_session_key(self):
        return self.__sessionKey

    def set_auth_level(self, auth_level):
        self.__auth_level = auth_level

    def set_auth_type(self, auth_type, callback=None):
        self.__auth_type = auth_type
        self.__auth_type_callback = callback

    def get_auth_type(self):
        return self.__auth_type

    def set_max_tfrag(self, size):
        self.__max_xmit_size = size

    def get_credentials(self):
        return (
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            self.__TGT,
            self.__TGS,
        )

    def set_credentials(
        self,
        username,
        password,
        domain="",
        lmhash="",
        nthash="",
        aesKey="",
        TGT=None,
        TGS=None,
    ):
        self.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__aesKey = aesKey
        self.__TGT = TGT
        self.__TGS = TGS
        if lmhash != "" or nthash != "":
            if len(lmhash) % 2:
                lmhash = "0%s" % lmhash
            if len(nthash) % 2:
                nthash = "0%s" % nthash
            try:  # just in case they were converted already
                self.__lmhash = unhexlify(lmhash)
                self.__nthash = unhexlify(nthash)
            except:
                self.__lmhash = lmhash
                self.__nthash = nthash
                pass

    def bind(
        self,
        iface_uuid,
        alter=0,
        bogus_binds=0,
        transfer_syntax=("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0"),
    ):
        bind = MSRPCBind()
        # item['TransferSyntax']['Version'] = 1
        ctx = self._ctx
        for i in range(bogus_binds):
            item = CtxItem()
            item["ContextID"] = ctx
            item["TransItems"] = 1
            item["ContextID"] = ctx
            # We generate random UUIDs for bogus binds
            item["AbstractSyntax"] = generate() + stringver_to_bin("2.0")
            item["TransferSyntax"] = uuidtup_to_bin(transfer_syntax)
            bind.addCtxItem(item)
            self._ctx += 1
            ctx += 1

        # The true one :)
        item = CtxItem()
        item["AbstractSyntax"] = iface_uuid
        item["TransferSyntax"] = uuidtup_to_bin(transfer_syntax)
        item["ContextID"] = ctx
        item["TransItems"] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet["type"] = MSRPC_BIND
        packet["pduData"] = bind.getData()
        packet["call_id"] = self.__callid

        if alter:
            packet["type"] = MSRPC_ALTERCTX

        if self.__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            if (self.__username is None) or (self.__password is None):
                (
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__lmhash,
                    self.__nthash,
                    self.__aesKey,
                    self.__TGT,
                    self.__TGS,
                ) = self._transport.get_credentials()

            if self.__auth_type == RPC_C_AUTHN_WINNT:
                auth = ntlm.getNTLMSSPType1(
                    "",
                    "",
                    signingRequired=True,
                    use_ntlmv2=self._transport.doesSupportNTLMv2(),
                )
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                from impacket.dcerpc.v5 import nrpc

                auth = nrpc.getSSPType1(
                    self.__username[:-1], self.__domain, signingRequired=True
                )
            elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                self.__cipher, self.__sessionKey, auth = kerberosv5.getKerberosType1(
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__lmhash,
                    self.__nthash,
                    self.__aesKey,
                    self.__TGT,
                    self.__TGS,
                    self._transport.getRemoteName(),
                    self._transport.get_kdcHost(),
                )
            else:
                raise DCERPCException("Unsupported auth_type 0x%x" % self.__auth_type)

            sec_trailer = SEC_TRAILER()
            sec_trailer["auth_type"] = self.__auth_type
            sec_trailer["auth_level"] = self.__auth_level
            sec_trailer["auth_ctx_id"] = self._ctx + 79231

            pad = (4 - (len(packet.get_packet()) % 4)) % 4
            if pad != 0:
                packet["pduData"] += b"\xff" * pad
                sec_trailer["auth_pad_len"] = pad

            packet["sec_trailer"] = sec_trailer
            packet["auth_data"] = auth

        self._transport.send(packet.get_packet())

        s = self._transport.recv()

        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0  # mmm why not None?

        if resp["type"] == MSRPC_BINDACK or resp["type"] == MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(resp.getData())
        elif resp["type"] == MSRPC_BINDNAK or resp["type"] == MSRPC_FAULT:
            if resp["type"] == MSRPC_FAULT:
                resp = MSRPCRespHeader(resp.getData())
                status_code = unpack("<L", resp["pduData"][:4])[0]
            else:
                resp = MSRPCBindNak(resp["pduData"])
                status_code = resp["RejectedReason"]
            if status_code in rpc_status_codes:
                raise DCERPCException(error_code=status_code)
            elif status_code in rpc_provider_reason:
                raise DCERPCException(
                    "Bind context rejected: %s" % rpc_provider_reason[status_code]
                )
            else:
                raise DCERPCException(
                    "Unknown DCE RPC fault status code: %.8x" % status_code
                )
        else:
            raise DCERPCException(
                "Unknown DCE RPC packet type received: %d" % resp["type"]
            )

        # check ack results for each context, except for the bogus ones
        for ctx in range(bogus_binds + 1, bindResp["ctx_num"] + 1):
            ctxItems = bindResp.getCtxItem(ctx)
            if ctxItems["Result"] != 0:
                msg = "Bind context %d rejected: " % ctx
                msg += rpc_cont_def_result.get(
                    ctxItems["Result"],
                    "Unknown DCE RPC context result code: %.4x" % ctxItems["Result"],
                )
                msg += "; "
                reason = bindResp.getCtxItem(ctx)["Reason"]
                msg += rpc_provider_reason.get(
                    reason, "Unknown reason code: %.4x" % reason
                )
                if (ctxItems["Result"], reason) == (
                    2,
                    1,
                ):  # provider_rejection, abstract syntax not supported
                    msg += " (this usually means the interface isn't listening on the given endpoint)"
                raise DCERPCException(msg)

            # Save the transfer syntax for later use
            self.transfer_syntax = ctxItems["TransferSyntax"]

        # The received transmit size becomes the client's receive size, and the received receive size becomes the client's transmit size.
        self.__max_xmit_size = bindResp["max_rfrag"]

        if self.__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            if self.__auth_type == RPC_C_AUTHN_WINNT:
                response, self.__sessionKey = ntlm.getNTLMSSPType3(
                    auth,
                    bindResp["auth_data"],
                    self.__username,
                    self.__password,
                    self.__domain,
                    self.__lmhash,
                    self.__nthash,
                    use_ntlmv2=self._transport.doesSupportNTLMv2(),
                )
                self.__flags = response["flags"]
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                response = None
            elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                self.__cipher, self.__sessionKey, response = (
                    kerberosv5.getKerberosType3(
                        self.__cipher, self.__sessionKey, bindResp["auth_data"]
                    )
                )

            self.__sequence = 0

            if self.__auth_level in (
                RPC_C_AUTHN_LEVEL_CONNECT,
                RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            ):
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        self.__clientSigningKey = ntlm.SIGNKEY(
                            self.__flags, self.__sessionKey
                        )
                        self.__serverSigningKey = ntlm.SIGNKEY(
                            self.__flags, self.__sessionKey, b"Server"
                        )
                        self.__clientSealingKey = ntlm.SEALKEY(
                            self.__flags, self.__sessionKey
                        )
                        self.__serverSealingKey = ntlm.SEALKEY(
                            self.__flags, self.__sessionKey, b"Server"
                        )
                        # Preparing the keys handle states
                        cipher3 = ARC4.new(self.__clientSealingKey)
                        self.__clientSealingHandle = cipher3.encrypt
                        cipher4 = ARC4.new(self.__serverSealingKey)
                        self.__serverSealingHandle = cipher4.encrypt
                    else:
                        # Same key for everything
                        self.__clientSigningKey = self.__sessionKey
                        self.__serverSigningKey = self.__sessionKey
                        self.__clientSealingKey = self.__sessionKey
                        self.__serverSealingKey = self.__sessionKey
                        cipher = ARC4.new(self.__clientSigningKey)
                        self.__clientSealingHandle = cipher.encrypt
                        self.__serverSealingHandle = cipher.encrypt
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    if self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                        self.__confounder = b""
                    else:
                        self.__confounder = b"12345678"

            sec_trailer = SEC_TRAILER()
            sec_trailer["auth_type"] = self.__auth_type
            sec_trailer["auth_level"] = self.__auth_level
            sec_trailer["auth_ctx_id"] = self._ctx + 79231

            if response is not None:
                if self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    alter_ctx = MSRPCHeader()
                    alter_ctx["type"] = MSRPC_ALTERCTX
                    alter_ctx["pduData"] = bind.getData()
                    alter_ctx["sec_trailer"] = sec_trailer
                    alter_ctx["auth_data"] = response
                    self._transport.send(alter_ctx.get_packet(), forceWriteAndx=1)
                    self.__gss = gssapi.GSSAPI(self.__cipher)
                    self.__sequence = 0
                    self.recv()
                    self.__sequence = 0
                else:
                    auth3 = MSRPCHeader()
                    auth3["type"] = MSRPC_AUTH3
                    # pad (4 bytes): Can be set to any arbitrary value when set and MUST be
                    # ignored on receipt. The pad field MUST be immediately followed by a
                    # sec_trailer structure whose layout, location, and alignment are as
                    # specified in section 2.2.2.11
                    auth3["pduData"] = b"    "
                    auth3["sec_trailer"] = sec_trailer
                    auth3["auth_data"] = response.getData()

                    # Use the same call_id
                    self.__callid = resp["call_id"]
                    auth3["call_id"] = self.__callid
                    self._transport.send(auth3.get_packet(), forceWriteAndx=1)

            self.__callid += 1

        return resp  # means packet is signed, if verifier is wrong it fails

    def _transport_send(self, rpc_packet, forceWriteAndx=0, forceRecv=0):
        rpc_packet["ctx_id"] = self._ctx
        rpc_packet["sec_trailer"] = b""
        rpc_packet["auth_data"] = b""

        if self.__auth_level in [
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        ]:
            # Dummy verifier, just for the calculations
            sec_trailer = SEC_TRAILER()
            sec_trailer["auth_type"] = self.__auth_type
            sec_trailer["auth_level"] = self.__auth_level
            sec_trailer["auth_pad_len"] = 0
            sec_trailer["auth_ctx_id"] = self._ctx + 79231

            pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
            if pad != 0:
                rpc_packet["pduData"] += b"\xbb" * pad
                sec_trailer["auth_pad_len"] = pad

            rpc_packet["sec_trailer"] = sec_trailer.getData()
            rpc_packet["auth_data"] = b" " * 16

            plain_data = rpc_packet["pduData"]
            if self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        # When NTLM2 is on, we sign the whole pdu, but encrypt just
                        # the data, not the dcerpc header. Weird..
                        sealedMessage, signature = ntlm.SEAL(
                            self.__flags,
                            self.__clientSigningKey,
                            self.__clientSealingKey,
                            rpc_packet.get_packet()[:-16],
                            plain_data,
                            self.__sequence,
                            self.__clientSealingHandle,
                        )
                    else:
                        sealedMessage, signature = ntlm.SEAL(
                            self.__flags,
                            self.__clientSigningKey,
                            self.__clientSealingKey,
                            plain_data,
                            plain_data,
                            self.__sequence,
                            self.__clientSealingHandle,
                        )
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    from impacket.dcerpc.v5 import nrpc

                    sealedMessage, signature = nrpc.SEAL(
                        plain_data,
                        self.__confounder,
                        self.__sequence,
                        self.__sessionKey,
                        False,
                    )
                elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    sealedMessage, signature = self.__gss.GSS_Wrap(
                        self.__sessionKey, plain_data, self.__sequence
                    )

                rpc_packet["pduData"] = sealedMessage
            elif self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        # Interesting thing.. with NTLM2, what is is signed is the
                        # whole PDU, not just the data
                        signature = ntlm.SIGN(
                            self.__flags,
                            self.__clientSigningKey,
                            rpc_packet.get_packet()[:-16],
                            self.__sequence,
                            self.__clientSealingHandle,
                        )
                    else:
                        signature = ntlm.SIGN(
                            self.__flags,
                            self.__clientSigningKey,
                            plain_data,
                            self.__sequence,
                            self.__clientSealingHandle,
                        )
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    from impacket.dcerpc.v5 import nrpc

                    signature = nrpc.SIGN(
                        plain_data,
                        self.__confounder,
                        self.__sequence,
                        self.__sessionKey,
                        False,
                    )
                elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    signature = self.__gss.GSS_GetMIC(
                        self.__sessionKey, plain_data, self.__sequence
                    )

            rpc_packet["sec_trailer"] = sec_trailer.getData()
            rpc_packet["auth_data"] = signature

            self.__sequence += 1

        self._transport.send(
            rpc_packet.get_packet(), forceWriteAndx=forceWriteAndx, forceRecv=forceRecv
        )

    def send(self, data):
        if isinstance(data, MSRPCHeader) is not True:
            # Must be an Impacket, transform to structure
            data = DCERPC_RawCall(data.OP_NUM, data.get_packet())

        try:
            if data["uuid"] != b"":
                data["flags"] |= PFC_OBJECT_UUID
        except:
            # Structure doesn't have uuid
            pass
        data["ctx_id"] = self._ctx
        data["call_id"] = self.__callid
        data["alloc_hint"] = len(data["pduData"])
        # We should fragment PDUs if:
        # 1) Payload exceeds __max_xmit_size received during BIND response
        # 2) We'e explicitly fragmenting packets with lower values
        should_fragment = False

        # Let's decide what will drive fragmentation for this request
        if self._max_user_frag > 0:
            # User set a frag size, let's compare it with the max transmit size agreed when binding the interface
            fragment_size = min(self._max_user_frag, self.__max_xmit_size)
        else:
            fragment_size = self.__max_xmit_size

        # Sanity check. Fragmentation can't be too low, otherwise sec_trailer won't fit

        if self.__auth_level in [
            RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        ]:
            if fragment_size <= 8:
                # Minimum pdu fragment size is 8, important when doing PKT_INTEGRITY/PRIVACY. We need a minimum size of 8
                # (Kerberos)
                fragment_size = 8

        # ToDo: Better calculate the size needed. Now I'm setting a number that surely is enough for Kerberos and NTLM
        # ToDo: trailers, both for INTEGRITY and PRIVACY. This means we're not truly honoring the user's frag request.
        if len(data["pduData"]) + 128 > fragment_size:
            should_fragment = True
            if fragment_size + 128 > self.__max_xmit_size:
                fragment_size = self.__max_xmit_size - 128

        if should_fragment:
            packet = data["pduData"]
            offset = 0

            while 1:
                toSend = packet[offset : offset + fragment_size]
                if not toSend:
                    break
                if offset == 0:
                    data["flags"] |= PFC_FIRST_FRAG
                else:
                    data["flags"] &= ~PFC_FIRST_FRAG
                offset += len(toSend)
                if offset >= len(packet):
                    data["flags"] |= PFC_LAST_FRAG
                else:
                    data["flags"] &= ~PFC_LAST_FRAG
                data["pduData"] = toSend
                self._transport_send(
                    data, forceWriteAndx=1, forceRecv=data["flags"] & PFC_LAST_FRAG
                )
        else:
            self._transport_send(data)
        self.__callid += 1

    def recv(self):
        finished = False
        forceRecv = 0
        retAnswer = b""
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for
            # TCP/UDP Transports
            response_data = self._transport.recv(forceRecv, count=MSRPCRespHeader._SIZE)
            response_header = MSRPCRespHeader(response_data)
            # Ok, there might be situation, especially with large packets, that
            # the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while len(response_data) < response_header["frag_len"]:
                response_data += self._transport.recv(
                    forceRecv, count=(response_header["frag_len"] - len(response_data))
                )

            off = response_header.get_header_size()

            if (
                response_header["type"] == MSRPC_FAULT
                and response_header["frag_len"] >= off + 4
            ):
                status_code = unpack("<L", response_data[off : off + 4])[0]
                if status_code in rpc_status_codes:
                    raise DCERPCException(rpc_status_codes[status_code])
                elif status_code & 0xFFFF in rpc_status_codes:
                    raise DCERPCException(rpc_status_codes[status_code & 0xFFFF])
                else:
                    if status_code in hresult_errors.ERROR_MESSAGES:
                        error_msg_short = hresult_errors.ERROR_MESSAGES[status_code][0]
                        error_msg_verbose = hresult_errors.ERROR_MESSAGES[status_code][
                            1
                        ]
                        raise DCERPCException(
                            "%s - %s" % (error_msg_short, error_msg_verbose)
                        )
                    else:
                        raise DCERPCException(
                            "Unknown DCE RPC fault status code: %.8x" % status_code
                        )

            if response_header["flags"] & PFC_LAST_FRAG:
                # No need to reassembly DCERPC
                finished = True
            else:
                # Forcing Read Recv, we need more packets!
                forceRecv = 1

            answer = response_data[off:]
            auth_len = response_header["auth_len"]
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data=auth_data)
                answer = answer[:-auth_len]

                if sec_trailer["auth_level"] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        if (
                            self.__flags
                            & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                        ):
                            # TODO: FIX THIS, it's not calculating the signature well
                            # Since I'm not testing it we don't care... yet
                            answer, signature = ntlm.SEAL(
                                self.__flags,
                                self.__serverSigningKey,
                                self.__serverSealingKey,
                                answer,
                                answer,
                                self.__sequence,
                                self.__serverSealingHandle,
                            )
                        else:
                            answer, signature = ntlm.SEAL(
                                self.__flags,
                                self.__serverSigningKey,
                                self.__serverSealingKey,
                                answer,
                                answer,
                                self.__sequence,
                                self.__serverSealingHandle,
                            )
                            self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                        from impacket.dcerpc.v5 import nrpc

                        answer, cfounder = nrpc.UNSEAL(
                            answer,
                            auth_data[len(sec_trailer) :],
                            self.__sessionKey,
                            False,
                        )
                        self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                        if self.__sequence > 0:
                            answer, cfounder = self.__gss.GSS_Unwrap(
                                self.__sessionKey,
                                answer,
                                self.__sequence,
                                direction="init",
                                authData=auth_data,
                            )

                elif sec_trailer["auth_level"] == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        ntlmssp = auth_data[12:]
                        if (
                            self.__flags
                            & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                        ):
                            signature = ntlm.SIGN(
                                self.__flags,
                                self.__serverSigningKey,
                                answer,
                                self.__sequence,
                                self.__serverSealingHandle,
                            )
                        else:
                            signature = ntlm.SIGN(
                                self.__flags,
                                self.__serverSigningKey,
                                ntlmssp,
                                self.__sequence,
                                self.__serverSealingHandle,
                            )
                            # Yes.. NTLM2 doesn't increment sequence when receiving
                            # the packet :P
                            self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                        from impacket.dcerpc.v5 import nrpc

                        ntlmssp = auth_data[12:]
                        signature = nrpc.SIGN(
                            ntlmssp,
                            self.__confounder,
                            self.__sequence,
                            self.__sessionKey,
                            False,
                        )
                        self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                        # Do NOT increment the sequence number when Signing Kerberos
                        # self.__sequence += 1
                        pass

                if sec_trailer["auth_pad_len"]:
                    answer = answer[: -sec_trailer["auth_pad_len"]]

            retAnswer += answer
        return retAnswer

    def alter_ctx(self, newUID, bogus_binds=0):
        answer = self.__class__(self._transport)

        answer.set_credentials(
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            self.__TGT,
            self.__TGS,
        )
        answer.set_auth_type(self.__auth_type)
        answer.set_auth_level(self.__auth_level)

        answer.set_ctx_id(self._ctx + 1)
        answer.__callid = self.__callid
        answer.bind(
            newUID,
            alter=1,
            bogus_binds=bogus_binds,
            transfer_syntax=bin_to_uuidtup(self.transfer_syntax),
        )
        return answer


class DCERPC_RawCall(MSRPCRequestHeader):
    def __init__(self, op_num, data=b"", uuid=None):
        MSRPCRequestHeader.__init__(self)
        self["op_num"] = op_num
        self["pduData"] = data
        if uuid is not None:
            self["flags"] |= PFC_OBJECT_UUID
            self["uuid"] = uuid

    def setData(self, data):
        self["pduData"] = data


# 2.2.6 Type Serialization Version 1
class CommonHeader(NDRSTRUCT):
    structure = (
        ("Version", UCHAR),
        ("Endianness", UCHAR),
        ("CommonHeaderLength", USHORT),
        ("Filler", ULONG),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self["Version"] = 1
            self["Endianness"] = 0x10
            self["CommonHeaderLength"] = 8
            self["Filler"] = 0xCCCCCCCC


class PrivateHeader(NDRSTRUCT):
    structure = (
        ("ObjectBufferLength", ULONG),
        ("Filler", ULONG),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self["Filler"] = 0xCCCCCCCC


class TypeSerialization1(NDRSTRUCT):
    commonHdr = (
        ("CommonHeader", CommonHeader),
        ("PrivateHeader", PrivateHeader),
    )

    def getData(self, soFar=0):
        self["PrivateHeader"]["ObjectBufferLength"] = (
            len(NDRSTRUCT.getData(self, soFar))
            + len(NDRSTRUCT.getDataReferents(self, soFar))
            - len(self["CommonHeader"])
            - len(self["PrivateHeader"])
        )
        return NDRSTRUCT.getData(self, soFar)


class DCERPCServer(Thread):
    """
    A minimalistic DCERPC Server, mainly used by the smbserver, for now. Might be useful
    for other purposes in the future, but we should do it way stronger.
    If you want to implement a DCE Interface Server, use this class as the base class
    """

    def __init__(self):
        Thread.__init__(self)
        self._listenPort = 0
        self._listenAddress = "127.0.0.1"
        self._listenUUIDS = {}
        self._boundUUID = b""
        self._sock = None
        self._clientSock = None
        self._callid = 1
        self._max_frag = None
        self._max_xmit_size = 4280
        self.__log = LOG
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress, self._listenPort))

    def log(self, msg, level=logging.INFO):
        self.__log.log(level, msg)

    def addCallbacks(self, ifaceUUID, secondaryAddr, callbacks):
        """
        adds a call back to a UUID/opnum call

        :param uuid ifaceUUID: the interface UUID
        :param string secondaryAddr: the secondary address to answer as part of the bind request (e.g. \\\\PIPE\\\\srvsvc)
        :param dict callbacks: the callbacks for each opnum. Format is [opnum] = callback
        """
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)] = {}
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)]["SecondaryAddr"] = secondaryAddr
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)]["CallBacks"] = callbacks
        self.log("Callback added for UUID %s V:%s" % ifaceUUID)

    def setListenPort(self, portNum):
        self._listenPort = portNum
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress, self._listenPort))

    def getListenPort(self):
        return self._sock.getsockname()[1]

    def recv(self):
        finished = False
        retAnswer = b""
        response_data = b""
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for TCP/UDP Transports
            response_data = self._clientSock.recv(MSRPCRespHeader._SIZE)
            # No data?, connection might have closed
            if response_data == b"":
                return None
            response_header = MSRPCRespHeader(response_data)
            # Ok, there might be situation, especially with large packets,
            # that the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while len(response_data) < response_header["frag_len"]:
                response_data += self._clientSock.recv(
                    response_header["frag_len"] - len(response_data)
                )
            response_header = MSRPCRespHeader(response_data)
            if response_header["flags"] & PFC_LAST_FRAG:
                # No need to reassembly DCERPC
                finished = True
            answer = response_header["pduData"]
            auth_len = response_header["auth_len"]
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data=auth_data)
                answer = answer[:-auth_len]
                if sec_trailer["auth_pad_len"]:
                    answer = answer[: -sec_trailer["auth_pad_len"]]

            retAnswer += answer
        return response_data

    def run(self):
        self._sock.listen(10)
        while True:
            self._clientSock, address = self._sock.accept()
            try:
                while True:
                    data = self.recv()
                    if data is None:
                        # No data.. connection closed
                        break
                    answer = self.processRequest(data)
                    if answer is not None:
                        self.send(answer)
            except Exception:
                # import traceback
                # traceback.print_exc()
                pass
            self._clientSock.close()

    def send(self, data):
        max_frag = self._max_frag
        if len(data["pduData"]) > self._max_xmit_size - 32:
            max_frag = (
                self._max_xmit_size - 32
            )  # XXX: 32 is a safe margin for auth data

        if self._max_frag:
            max_frag = min(max_frag, self._max_frag)
        if max_frag and len(data["pduData"]) > 0:
            packet = data["pduData"]
            offset = 0
            while 1:
                toSend = packet[offset : offset + max_frag]
                if not toSend:
                    break
                flags = 0
                if offset == 0:
                    flags |= PFC_FIRST_FRAG
                offset += len(toSend)
                if offset == len(packet):
                    flags |= PFC_LAST_FRAG
                data["flags"] = flags
                data["pduData"] = toSend
                self._clientSock.send(data.get_packet())
        else:
            self._clientSock.send(data.get_packet())
        self._callid += 1

    def bind(self, packet, bind):
        # Standard NDR Representation
        NDRSyntax = ("8a885d04-1ceb-11c9-9fe8-08002b104860", "2.0")
        resp = MSRPCBindAck()

        resp["type"] = MSRPC_BINDACK
        resp["flags"] = packet["flags"]
        resp["frag_len"] = 0
        resp["auth_len"] = 0
        resp["auth_data"] = b""
        resp["call_id"] = packet["call_id"]
        resp["max_tfrag"] = bind["max_tfrag"]
        resp["max_rfrag"] = bind["max_rfrag"]
        resp["assoc_group"] = 0x1234
        resp["ctx_num"] = 0

        data = bind["ctx_items"]
        ctx_items = b""
        resp["SecondaryAddrLen"] = 0
        for i in range(bind["ctx_num"]):
            result = MSRPC_CONT_RESULT_USER_REJECT
            item = CtxItem(data)
            data = data[len(item) :]

            # First we check the Transfer Syntax is NDR32, what we support
            if item["TransferSyntax"] == uuidtup_to_bin(NDRSyntax):
                # Now Check if the interface is what we listen
                reason = 1  # Default, Abstract Syntax not supported
                for j in self._listenUUIDS:
                    if item["AbstractSyntax"] == j:
                        # Match, we accept the bind request
                        resp["SecondaryAddr"] = self._listenUUIDS[
                            item["AbstractSyntax"]
                        ]["SecondaryAddr"]
                        resp["SecondaryAddrLen"] = len(resp["SecondaryAddr"]) + 1
                        reason = 0
                        self._boundUUID = j
            else:
                # Fail the bind request for this context
                reason = 2  # Transfer Syntax not supported
            if reason == 0:
                result = MSRPC_CONT_RESULT_ACCEPT
            if reason == 1:
                LOG.error(
                    "Bind request for an unsupported interface %s"
                    % bin_to_uuidtup(item["AbstractSyntax"])
                )

            resp["ctx_num"] += 1
            itemResult = CtxItemResult()
            itemResult["Result"] = result
            itemResult["Reason"] = reason
            itemResult["TransferSyntax"] = uuidtup_to_bin(NDRSyntax)
            ctx_items += itemResult.getData()

        resp["Pad"] = "A" * (
            (4 - ((resp["SecondaryAddrLen"] + MSRPCBindAck._SIZE) % 4)) % 4
        )
        resp["ctx_items"] = ctx_items
        resp["frag_len"] = len(resp.getData())

        self._clientSock.send(resp.getData())
        return None

    def processRequest(self, data):
        packet = MSRPCHeader(data)
        if packet["type"] == MSRPC_BIND:
            bind = MSRPCBind(packet["pduData"])
            self.bind(packet, bind)
            packet = None
        elif packet["type"] == MSRPC_REQUEST:
            request = MSRPCRequestHeader(data)
            response = MSRPCRespHeader(data)
            response["type"] = MSRPC_RESPONSE
            # Serve the opnum requested, if not, fails
            if request["op_num"] in self._listenUUIDS[self._boundUUID]["CallBacks"]:
                # Call the function
                returnData = self._listenUUIDS[self._boundUUID]["CallBacks"][
                    request["op_num"]
                ](request["pduData"])
                response["pduData"] = returnData
            else:
                LOG.error(
                    "Unsupported DCERPC opnum %d called for interface %s"
                    % (request["op_num"], bin_to_uuidtup(self._boundUUID))
                )
                response["type"] = MSRPC_FAULT
                response["pduData"] = pack("<L", 0x000006E4)
            response["frag_len"] = len(response)
            return response
        else:
            # Defaults to a fault
            packet = MSRPCRespHeader(data)
            packet["type"] = MSRPC_FAULT

        return packet
