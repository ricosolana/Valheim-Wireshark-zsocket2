-- completely refactored to consolidate fields
-- zs2.rpc.basic_field_name
-- Vector3
-- automatically generate x/y/z fields for each vector

--local types = assert(require("zs2_types"))
local fields = assert(require("zs2_field_wrappers"))
local prefabs = assert(require("zs2_prefabs"))
local constants = assert(require("zs2_constants"))

local proto = readers.get_proto()

local PORT = constants.PORT

return {
    [1233642074] = {
        name = "ServerHandshake"
    },
    [1021693670] = {
        name = "ClientHandshake",
        parser = function(body_range, packet_info, tree, offset)
            --[[
                Wireshark lua Fields:
                    are the visual representation

                    highlighting: also visual, but ties in with payload

                    add_packet_field: used for highlighting (but apparently try to avoid for simplicity)
                        https://osqa-ask.wireshark.org/questions/11750/is-there-a-lua-bug-that-prevents-byte-highlighting-upon-field-selection/

                intended usage (parsing)
                    field_wrapper: dict:
                        'field': raw ProtoField
                        'parser': reader: function()
                        --'size': primarily for primitive types
                            actually, incorporate with parser()

                    offset = field_wrapper:read(body_range, tree, offset)

                intended usage (declaring)
                    -- above...
                    local HIGHLIGHT = true
                    -- ...
                    
                    local wrapper = generator:uint8('peerinfo.userid', 'User ID', HIGHLIGHT)

                    local wrapper1 = generator:string('peerinfo.version', 'Version', HIGHLIGHT)
                        -- because wrapper is comprised of a e7-int, bytes
                        -- contain 2 fields, ids: 'peerinfo.version.length', 'peerinfo.version.payload'
            --]]
            --field_wrapper

            offset = fields["s2c_handshake.locked"]:parser(body_range, tree, offset)
            offset = fields["s2c_handshake.salt"]:parser(body_range, tree, offset)
        end
    },
    [-725574882] = {
        name = "PeerInfo",
        parser = function(body_range, packet_info, tree, offset)
        end
    }
}
