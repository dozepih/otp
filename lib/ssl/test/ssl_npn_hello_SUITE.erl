-module(ssl_npn_hello_SUITE).

%% Note: This directive should only be used in test suites.
-compile(export_all).
-include("ssl_handshake.hrl").
-include("ssl_record.hrl").
-include_lib("common_test/include/ct.hrl").

suite() -> [{ct_hooks,[ts_install_cth]}].

all() ->
    [encode_and_decode_npn_client_hello_test,
     encode_and_decode_npn_server_hello_test,
     encode_and_decode_client_hello_test,
     encode_and_decode_server_hello_test,
     create_server_hello_with_advertised_protocols_test,
     create_server_hello_with_no_advertised_protocols_test].


create_client_handshake(Npn) ->
    ssl_handshake:encode_handshake(#client_hello{
        client_version = {1, 2},
        random = <<1:256>>,
        session_id = <<>>,
        cipher_suites = "",
        compression_methods = "",
        next_protocol_negotiation = Npn,
        renegotiation_info = #renegotiation_info{}
    }, vsn).


encode_and_decode_client_hello_test(_Config) ->
    HandShakeData = create_client_handshake(undefined),
    {[{DecodedHandshakeMessage, _Raw}], _} = ssl_handshake:get_tls_handshake(list_to_binary(HandShakeData), <<>>),
    NextProtocolNegotiation = DecodedHandshakeMessage#client_hello.next_protocol_negotiation,
    NextProtocolNegotiation = undefined.

encode_and_decode_npn_client_hello_test(_Config) ->
    HandShakeData = create_client_handshake(#next_protocol_negotiation{extension_data = <<>>}),
    {[{DecodedHandshakeMessage, _Raw}], _} = ssl_handshake:get_tls_handshake(list_to_binary(HandShakeData), <<>>),
    NextProtocolNegotiation = DecodedHandshakeMessage#client_hello.next_protocol_negotiation,
    NextProtocolNegotiation = #next_protocol_negotiation{extension_data = <<>>}.

create_server_handshake(Npn) ->
    ssl_handshake:encode_handshake(#server_hello{
        server_version = {1, 2},
        random = <<1:256>>,
        session_id = <<>>,
        cipher_suite = <<1,2>>,
        compression_method = 1,
        next_protocol_negotiation = Npn,
        renegotiation_info = #renegotiation_info{}
    }, vsn).

encode_and_decode_server_hello_test(_Config) ->
    HandShakeData = create_server_handshake(undefined),
    {[{DecodedHandshakeMessage, _Raw}], _} = ssl_handshake:get_tls_handshake(list_to_binary(HandShakeData), <<>>),
    NextProtocolNegotiation = DecodedHandshakeMessage#server_hello.next_protocol_negotiation,
    NextProtocolNegotiation = undefined.

encode_and_decode_npn_server_hello_test(_Config) ->
    HandShakeData = create_server_handshake(#next_protocol_negotiation{extension_data = <<6, "spdy/2">>}),
    {[{DecodedHandshakeMessage, _Raw}], _} = ssl_handshake:get_tls_handshake(list_to_binary(HandShakeData), <<>>),
    NextProtocolNegotiation = DecodedHandshakeMessage#server_hello.next_protocol_negotiation,
    io:format("~p ~n", [NextProtocolNegotiation]),
    NextProtocolNegotiation = #next_protocol_negotiation{extension_data = <<6, "spdy/2">>}.

create_connection_states() ->
    #connection_states{
        pending_read = #connection_state{
            security_parameters = #security_parameters{
                server_random = <<1:256>>,
                compression_algorithm = 1,
                cipher_suite = <<1, 2>>
            }
        },

        current_read = #connection_state {
            secure_renegotiation = false
        }
    }.

create_server_hello_with_no_advertised_protocols_test(_Config) ->
    Hello = ssl_handshake:server_hello(<<>>, {3, 0}, create_connection_states(),  false, undefined),
    undefined = Hello#server_hello.next_protocol_negotiation.

create_server_hello_with_advertised_protocols_test(_Config) ->
    Hello = ssl_handshake:server_hello(<<>>, {3, 0}, create_connection_states(),  false, [<<"spdy/1">>, <<"http/1.0">>, <<"http/1.1">>]),
     #next_protocol_negotiation{extension_data = <<6, "spdy/1", 8, "http/1.0", 8, "http/1.1">>} = Hello#server_hello.next_protocol_negotiation.
