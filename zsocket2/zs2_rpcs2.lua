-- completely refactored to consolidate fields
-- zs2.rpc.basic_field_name
-- Vector3
-- automatically generate x/y/z fields for each vector

local types = assert(require("zs2_types"))
local wrappers = assert(require("zs2_field_wrappers"))
local prefabs = assert(require("zs2_prefabs"))
local constants = assert(require("zs2_constants"))

local proto = types.get_proto()

local PORT = constants.PORT

return {
    [0] = {
        name = "(KeepAlive)"
    },
    [1233642074] = {
        name = "ServerHandshake"
    },
    [1021693670] = {
        name = "ClientHandshake",
        -- TODO idea;
        --  instead of manually parsing these trivial RPCs,
        --  declare the fields just like with Valheims RPC handlers
        --  because the below is simply redundant, when reading one-by-one...
        parser = function(body_range, packet_info, tree, offset)
            offset = wrappers["s2c_handshake.locked"]:parser(body_range, tree, offset)
            offset = wrappers["s2c_handshake.salt"]:parser(body_range, tree, offset)
        end
    },
    [-725574882] = {
        name = "PeerInfo",
        parser = function(body_range, packet_info, tree, offset)
        end
    }
}
