/*
  普通のC#用のMRSラッパー。Unity用のMrs.csとは違って、UnityEngineやMonoBehaviourを必要としない。
 */

using System;
using System.Runtime.InteropServices;
using MrsConnectionId = System.UInt64;
using MrsServerId = System.UInt64;
using MrsContextId = System.UInt64;




    public static class Mrs3
    {
        public enum MrsConnectionType
        {
            TCP = 1,
            WS = 3,
            WSS = 4,
            MRU = 6,
        };

        public enum MrsErrorCode
        {
            NONE = 0,

            INVALID_ARGUMENT = -1001,
            NO_CONNECTION_FOUND = -1002,
            NO_MEMORY = -1003,
            BUFFER_FULL = -1004,
            NO_RECORD_ENCODER = -1005,
            RECORD_TOO_LONG = -1006,
            INVALID_CONTEXT_ID = -1007,
            INVALID_SERVER_ID = -1008,
            INVALID_CONNECTION_ID = -1009,
            OPENSSL_ERROR = -1010,
            PEM_TOO_LONG = -1011,
            PATH_TOO_LONG = -1012,
            CANT_OPEN_FILE = -1013,
            FILE_READ_ERROR = -1014,
            INTERNAL_ERROR = -1015,
            TLS_HANDSHAKE_NOT_FINISHED = -1016,
            DTLS_HANDSHAKE_NOT_FINISHED = -1017,
            MRU_NOT_INITIALIZED = -1018,
            CONNECT_FAILED = -1019,
            INVALID_ADDRESS = -1020,
            SOCKET_CREATE_ERROR = -1021,
            BIND_ERROR = -1022,
            TCP_LISTEN_ERROR = -1023,
            TOO_MANY_SERVER = -1024,
            INVALID_CONNECTION_TYPE = -1025,
            WS_HANDSHAKE_NOT_FINISHED = -1026,
            CANT_SEND_RAW_ON_WS = -1027,
            TCP_ACCEPT_ERROR = -1028,
            INVALID_RECORD_OPTION = -1029,
            WINSOCK_INIT_FAILED = -1030,
            WINSOCK_VERSION_NOT_SUPPORTED = -1031,
            CONNECTION_TIMEOUT = -1032,
            INVALID_POLLING_TYPE = -1033,
            KEEPALIVE_TIMEOUT = -1034,
            CANT_SEND_TO_CLOSED_CONNECTION = -1035,
            RECVBUF_FULL = -1036,
            BROKEN_PIPE = -1037
        };

        public enum MrsConnectionError
        {
            CONNECT_ERROR = 1,
            CONNECT_TIMEOUT = 2,
            WRITE_ERROR = 3,
            KEY_EXCHANGE_REQUEST_ERROR = 4,
            KEY_EXCHANGE_RESPONSE_ERROR = 5,
            PEER_CONNECTION_HARD_LIMIT_OVER = 6,
            CONNECTION_READBUF_SIZE_OVER = 7,
            KEEPALIVE_TIMEOUT = 8,
            PROTOCOL_ERROR = 9,
            READ_INVALID_RECORD_ERROR = 10,
            LISTEN_ERROR = 11,
            RESOLVE_ADDRESS_ERROR = 12,
            RESOLVE_ADDRESS_TIMEOUT = 13,
            WRITE_ERROR_MTU = 14,
        };

        public enum MrsTlsVerifyCertResult
        {
            TRUSTED = 1,
            UNTRUSTED = 0,
        };


        public delegate void MrsAcceptCallback(MrsServerId sv_id, IntPtr server_data, MrsConnectionId conn_id);

        public delegate void MrsConnectCallback(MrsConnectionId conn_id);

        public delegate void MrsKeyExchangeCallback(MrsConnectionId conn_id);

        public delegate void MrsDisconnectCallback(MrsConnectionId conn_id);

        public delegate void MrsErrorCallback(MrsConnectionId conn_id, MrsErrorCode code);

        public delegate void MrsServerErrorCallback(MrsServerId sv_id, MrsErrorCode code);

        public delegate void MrsReadRecordCallback(MrsConnectionId conn_id, byte optbits, UInt16 payload_type,
            IntPtr _payload, UInt32 payload_len);

        public delegate void MrsReadRawCallback(MrsConnectionId conn_id, IntPtr _data, UInt32 data_len);

        public delegate void MrsTlsVerifyCertResultCallback(MrsTlsVerifyCertResult result);

        //    [DllImport("mrs3")]
        //    public static extern void mru_enable_debug_print_command_types();

        //    [DllImport("mrs3")]
        //    public static extern void mru_set_global_loss_rate(float rate);

        [DllImport("mrs3")]
        public static extern bool mrs_initialize();

        [DllImport("mrs3")]
        public static extern void mrs_update();

        [DllImport("mrs3")]
        public static extern void mrs_finalize();

        [DllImport("mrs3")]
        public static extern MrsContextId mrs_context_create(Int32 maxcliconn);

        [DllImport("mrs3")]
        public static extern MrsConnectionId mrs_connect(MrsContextId ctx, MrsConnectionType type, String addr,
            UInt16 port, UInt32 timeout_msec);

        [DllImport("mrs3")]
        public static extern bool mrs_send_record(MrsConnectionId conn, byte optbits, UInt16 payload_type,
            IntPtr _payload, UInt32 payload_len);

        public static bool mrs_send_record(MrsConnectionId conn, byte optbits, UInt16 payload_type, byte[] payload,
            UInt32 payload_len)
        {
            IntPtr _payload = Marshal.AllocCoTaskMem((Int32) payload_len);
            if (0 < payload_len) Marshal.Copy(payload, 0, _payload, (Int32) payload_len);
            bool result = mrs_send_record(conn, optbits, payload_type, _payload, payload_len);
            Marshal.FreeCoTaskMem(_payload);
            return result;
        }

        [DllImport("mrs3")]
        public static extern void mrs_set_connect_callback(MrsConnectionId conn, MrsConnectCallback callback);

        [DllImport("mrs3")]
        public static extern void mrs_set_disconnect_callback(MrsConnectionId conn, MrsDisconnectCallback callback);

        [DllImport("mrs3")]
        public static extern void mrs_set_error_callback(MrsConnectionId conn, MrsErrorCallback callback);

        [DllImport("mrs3")]
        public static extern void mrs_set_read_record_callback(MrsConnectionId conn, MrsReadRecordCallback callback);

        [DllImport("mrs3")]
        public static extern void mrs_sleep(UInt32 sleep_msec);

        [DllImport("mrs3")]
        public static extern void mrs_connection_close(MrsConnectionId conn);

        [DllImport("mrs3")]
        public static extern UInt64 mrs_now_msec();

        [DllImport("mrs3")]
        public static extern IntPtr mrs_connection_enable_encryption(MrsConnectionId conn);

        [DllImport("mrs3")]
        public static extern void mrs_set_keyex_callback(MrsConnectionId conn, MrsKeyExchangeCallback callback);
        [DllImport("mrs3")]
        public static extern void mrs_set_tls_verify_cert_result_callback(MrsTlsVerifyCertResultCallback callback);

        /*
        [DllImport("mrs3")]
        public static extern bool mrs_connection_set_data(MrsConnectionId conn, IntPtr ptr);

        [DllImport("mrs3")]
        public static extern IntPtr mrs_connection_get_data(MrsConnectionId conn);
        */

        /*
        [DllImport("mrs3")]
        public static extern UInt32 mrs_get_connection_num();

        [DllImport("mrs3")]
        public static extern UInt32 mrs_server_get_connection_num( MrsServer server );
        */

        /*
        [DllImport("mrs3")]
        public static extern MrsServer mrs_server_create(MrsConnectionType type, String addr, UInt16 port,
            Int32 backlog);

        [DllImport("mrs3")]
        public static extern void mrs_server_set_new_connection_callback(MrsServer server,
            MrsNewConnectionCallback callback);



        [DllImport("mrs3")]
        public static extern void mrs_set_read_callback(MrsConnection connection, MrsReadCallback callback);

        [DllImport("mrs3")]
        public static extern bool mrs_connection_set_data(MrsConnection connection, IntPtr connection_data);

        [DllImport("mrs3")]
        public static extern IntPtr mrs_connection_get_data(MrsConnection connection);

        [DllImport("mrs3")]
        public static extern MrsConnectionType mrs_connection_get_type(MrsConnection connection);

        [DllImport("mrs3")]
        public static extern IntPtr mrs_connection_get_path(MrsConnection connection);

        [DllImport("mrs3")]
        public static extern bool mrs_connection_is_connected(MrsConnection connection);

        [DllImport("mrs3")]
        public static extern bool mrs_connection_set_readbuf_max_size(MrsConnection connection, UInt32 value);

        [DllImport("mrs3")]
        public static extern UInt32 mrs_connection_get_readbuf_max_size(MrsConnection connection);


        [DllImport("mrs3")]
        public static extern bool mrs_write(MrsConnection connection, IntPtr _data, UInt32 data_len);

        public static bool mrs_write(MrsConnection connection, byte[] data, UInt32 data_len)
        {
            IntPtr _data = Marshal.AllocCoTaskMem((Int32) data_len);
            if (0 < data_len) Marshal.Copy(data, 0, _data, (Int32) data_len);
            bool result = mrs_write(connection, _data, data_len);
            Marshal.FreeCoTaskMem(_data);
            return result;
        }

        [DllImport("mrs3")]
        public static extern UInt32 mrs_connection_get_remote_address(MrsConnection connection, IntPtr outaddr,
            UInt32 outaddrmax, IntPtr outport);

        public static void mrs_connection_get_remote_address(MrsConnection connection, ref string outaddr,
            ref UInt16 outport)
        {
            IntPtr addrbuf = Marshal.AllocCoTaskMem(48);
            IntPtr portbuf = Marshal.AllocCoTaskMem(2);
            uint len = mrs_connection_get_remote_address(connection, addrbuf, 48, portbuf);
            byte[] addrbytes = ToBytes(addrbuf, len);
            outaddr = ToString(addrbytes);
            byte[] portbytes = ToBytes(portbuf, 2);
            outport = (ushort) (portbytes[0] * 256 + portbytes[1]);
            Marshal.FreeCoTaskMem(addrbuf);
            Marshal.FreeCoTaskMem(portbuf);
        }

        [DllImport("mrs3")]
        public static extern void mrs_udp_set_mtu(UInt32 value);

        [DllImport("mrs3")]
        public static extern UInt32 mrs_udp_get_mtu();

        [DllImport("mrs3")]
        public static extern MrsCipher mrs_cipher_create(MrsCipherType type);

        [DllImport("mrs3")]
        public static extern void mrs_set_cipher(MrsConnection connection, MrsCipher cipher);

        [DllImport("mrs3")]
        public static extern bool mrs_key_exchange(MrsConnection connection, MrsKeyExchangeCallback callback);


        protected static MrsLogLevel s_LogOutputLevel;
        protected static MrsLogOutputCallback s_LogOutputCallback;

        public static MrsLogLevel mrs_get_output_log_level()
        {
            return s_LogOutputLevel;
        }

        public static void mrs_set_output_log_level(MrsLogLevel level)
        {
            s_LogOutputLevel = level;
        }

        public static void mrs_output_log(MrsLogLevel level, String msg)
        {
            if (level <= s_LogOutputLevel) s_LogOutputCallback(level, msg);
        }

        public static MrsLogOutputCallback mrs_get_log_callback()
        {
            return s_LogOutputCallback;
        }

        [DllImport("mrs3")]
        public static extern void mrs_set_log_callback(IntPtr callback);

        public static void mrs_set_log_callback(MrsLogOutputCallback callback)
        {
            mrs_set_log_callback(Marshal.GetFunctionPointerForDelegate(callback));
            s_LogOutputCallback = callback;
        }

        public static void mrs_console_log(MrsLogLevel level, String msg)
        {
            switch (level)
            {
                case MrsLogLevel.DEBUG:
                case MrsLogLevel.INFO:
                case MrsLogLevel.NOTICE:
                {
                    Console.WriteLine(msg);
                }
                    break;

                case MrsLogLevel.WARNING:
                {
                    Console.WriteLine(msg);
                }
                    break;

                default:
                {
                    Console.WriteLine(msg);
                }
                    break;
            }
        }

        [DllImport("mrs3")]
        public static extern MrsError mrs_get_last_error();

        [DllImport("mrs3")]
        public static extern IntPtr mrs_get_error_string(MrsError error);

        [DllImport("mrs3")]
        public static extern IntPtr mrs_get_connection_error_string(MrsConnectionError error);


        [DllImport("mrs3")]
        public static extern void mrs_set_ssl_certificate_data(String data);

        [DllImport("mrs3")]
        public static extern void mrs_set_ssl_private_key_data(String data);

        [DllImport("mrs3")]
        public static extern void mrs_set_keep_alive_update_msec(UInt32 update_msec);

        [DllImport("mrs3")]
        public static extern UInt32 mrs_get_keep_alive_update_msec();

        [DllImport("mrs3")]
        public static extern void mrs_set_version(String key, UInt32 value);

        [DllImport("mrs3")]
        public static extern UInt32 mrs_get_version(String key);

        [DllImport("mrs3")]
        public static extern UInt32 mrs_connection_get_remote_version(MrsConnection connection, String key);

        // [unity]
        public static String ToString(byte[] value)
        {
            return System.Text.Encoding.UTF8.GetString(value).TrimEnd('\0');
        }

        public static String ToString(IntPtr value)
        {
            return Marshal.PtrToStringAnsi(value);
        }

        public static byte[] ToBytes(String value)
        {
            return System.Text.Encoding.UTF8.GetBytes(value);
        }

        public static byte[] ToBytes(IntPtr value, UInt32 value_len)
        {
            byte[] result = new byte[value_len];
            if (0 < value_len) Marshal.Copy(value, result, 0, (Int32) value_len);
            return result;
        }

        public static byte ToUInt8(String value)
        {
            byte result = 0;
            byte.TryParse(value, out result);
            return result;
        }

        public static UInt16 ToUInt16(String value)
        {
            UInt16 result = 0;
            UInt16.TryParse(value, out result);
            return result;
        }

        public static UInt32 ToUInt32(String value)
        {
            UInt32 result = 0;
            UInt32.TryParse(value, out result);
            return result;
        }

        public static UInt64 ToUInt64(String value)
        {
            UInt64 result = 0;
            UInt64.TryParse(value, out result);
            return result;
        }

        public static sbyte ToInt8(String value)
        {
            sbyte result = 0;
            sbyte.TryParse(value, out result);
            return result;
        }

        public static Int16 ToInt16(String value)
        {
            Int16 result = 0;
            Int16.TryParse(value, out result);
            return result;
        }

        public static Int32 ToInt32(String value)
        {
            Int32 result = 0;
            Int32.TryParse(value, out result);
            return result;
        }

        public static Int64 ToInt64(String value)
        {
            Int64 result = 0;
            Int64.TryParse(value, out result);
            return result;
        }
        */

        private static void __mrs_setup__()
        {
        }

        static Mrs3()
        {
            __mrs_setup__();

            //        s_LogOutputLevel = MrsLogLevel.DEBUG;
            //        mrs_set_log_callback( mrs_console_log );
        }
    }

