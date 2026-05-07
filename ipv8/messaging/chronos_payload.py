import time

from ipv8.messaging.lazy_payload import VariablePayload, VariablePayloadWID

# VariablePayload, but adds some more functionality on top
# such as a timestamp, we need timestamps for node coordination. 
# send_timestamp is reserved
class ChronosPayloadWID(VariablePayloadWID):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __init__(self, var_payload: VariablePayload, timestamp_names=[]):
        self.msg_id=var_payload.msg_id

        self.format_list=var_payload.format_list
        self.format_list.append("d")

        self.names = self.names
        self.names.append("send_timestamp")

        for name in timestamp_names:
            if name not in self.names:
                self.format_list.append("d")
                self.names.append(name)




        
    # overrides previous value
    def write_timestamp(self, name:str):
        self.timestamps[name] = time.time()
    def add_custom_timestamp(self, name, timestamp):
        if name not in self.timestamps:
            print("this timestamp field was not reserved for this packet")
        

        
