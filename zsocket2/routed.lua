-- routedrpcs

local readers = assert(require("readers"))
local fields = assert(require("fields"))
local prefabs = assert(require("prefabs"))
local constants = assert(require("constants"))

local proto = readers.get_proto()

local PORT = constants.PORT

return {

    [-1090292557] = {
        name = "GlobalKeys",
        parser = function(body_range, packet_info, tree, offset)
            local count_range = body_range(offset, 4)
            local count = count_range:le_int()
            tree:add_packet_field(fields.routedrpc_globalkeys_count, count_range, ENC_LITTLE_ENDIAN)
            offset = offset + 4
            
            for i=1, count do
                -- read count elements from list<string>
                offset = readers.addString(body_range, tree, "Key", fields.routedrpc_globalkeys_key, offset)
            end
            
        end
    },

}
