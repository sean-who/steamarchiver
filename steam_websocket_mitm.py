from gzip import GzipFile
from io import BytesIO
from mitmproxy import ctx, http
from steam.core.msg import Msg, MsgProto
from steam.enums.emsg import EMsg
from steam.utils.proto import clear_proto_bit, is_proto
import struct

def websocket_message(flow: http.HTTPFlow):
    message = flow.websocket.messages[-1]
    emsg_id = struct.unpack_from("<I", message.content)[0]
    emsg = EMsg(clear_proto_bit(emsg_id))
    source = "client" if message.from_client else "server"
    if (emsg in (EMsg.ChannelEncryptRequest, EMsg.ChannelEncryptResponse, EMsg.ChannelEncryptResult)):
        with open("./wstraffic.log", "a") as f:
            f.write(f"\n\tMessage {emsg} sent by {source}: {Msg(emsg, message.content, parse=True)}")
    else:
        if is_proto(emsg_id):
            if (emsg == EMsg.Multi):
                multi = MsgProto(emsg, message.content, parse=True)
                if multi.body.size_unzipped:
                    # this message is gzipped
                    with GzipFile(fileobj=BytesIO(multi.body.message_body)) as f: multi = f.read()
                else: # raw message
                    multi = multi.body.message_body
                # split message into multiple
                while len(multi) > 0:
                    multi_msg_length = struct.unpack_from("<I", multi)[0]
                    multi_msg_raw = multi[4:4+multi_msg_length]
                    multi_msg_id = struct.unpack_from("<I", multi_msg_raw)[0]
                    multi_msg_emsg = EMsg(clear_proto_bit(multi_msg_id))
                    if is_proto(multi_msg_id):
                        with open("./wstraffic.log", "a") as f:
                            f.write(f"\n\tProtobuf message (in multi) {emsg} sent by {source}: {MsgProto(multi_msg_emsg, multi_msg_raw, parse=True)}")
                    else:
                        with open("./wstraffic.log", "a") as f:
                            f.write(f"\n\tMessage {emsg} (in multi) sent by {source}: {Msg(multi_msg_emsg, multi_msg_raw, extended=True, parse=True)}")
                    multi = multi[4+multi_msg_length:]
            else:
                with open("./wstraffic.log", "a") as f:
                    f.write(f"\n\tProtobuf message {emsg} sent by {source}: {MsgProto(emsg, message.content, parse=True)}")
        else:
            with open("./wstraffic.log", "a") as f:
                f.write(f"\n\tMessage {emsg} sent by {source}: {Msg(emsg, message.content, extended=True, parse=True)}")
