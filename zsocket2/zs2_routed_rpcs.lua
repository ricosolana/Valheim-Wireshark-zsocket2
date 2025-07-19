local types = assert(require("zs2_types"))
local fields = assert(require("zs2_field_wrappers"))
local prefabs = assert(require("zs2_prefabs"))
local constants = assert(require("zs2_constants"))

local proto = readers.get_proto()

local PORT = constants.PORT

return {
    [199378019] = {
        name = "DestroyZDO",
        parser = function(body_range, packet_info, tree, offset)
            --tree:add_packet_field(fields.clienthandshake_haspassword, body_range:range(offset, 1), ENC_LITTLE_ENDIAN)
            --offset = offset + 1
            --
            --offset = readers.addString(body_range, tree, "Password Salt", fields.clienthandshake_passwordsalt, offset)
        end
    }
}
