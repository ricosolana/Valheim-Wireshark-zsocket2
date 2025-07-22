-- completely refactored to consolidate fields
-- zs2.rpc.basic_field_name
-- Vector3
-- automatically generate x/y/z fields for each vector

local Types = assert(require("zs2_types"))
local Wrappers = assert(require("zs2_field_wrappers"))
local Prefabs = assert(require("zs2_prefabs"))
local Constants = assert(require("zs2_constants"))
local RoutedRpcs = assert(require("zs2_routed_rpcs"))

local proto = Types.get_proto()

local PORT = Constants.PORT
local NAME = Constants.NAME

-- function(class_key, filter_id, name, base_optional)
local gen = Types.generator
local compile = function(wrapper_array)
    local res = {}

    for i, wrapper in ipairs(wrapper_array) do
        res[wrapper.sub_filter_id] = wrapper
    end

    return res
end

return {
    [0] = {
        name = "(KeepAlive)",
        params = {
            gen("bool", "keepalive.server", "(Im) Server")
        }
    },
    [1233642074] = {
        name = "ServerHandshake"
        -- no params
    },
    [1021693670] = {
        name = "ClientHandshake",
        params = {
            -- TODO
            -- declare ordered parameters here:
            gen("bool", "s2c_handshake.locked", "Has Password"),
            gen("string", "s2c_handshake.salt", "Password Salt")
        }
    },
    [-725574882] = {
        name = "PeerInfo",
        fields = compile {
            gen("int64", "peerinfo.user_id", "User ID"),
            gen("string", "peerinfo.version", "Game Version"),
            gen("uint32", "peerinfo.network_version", "Network Version"),
            gen("vec3", "peerinfo.ref_pos", "Reference Position"),
            gen("string", "peerinfo.name", "Character Name"),
            gen("string", "peerinfo.password", "Password (MD5)"),
            gen("bytes", "peerinfo.ticket", "Session Ticket"),
            gen("string", "peerinfo.world", "World Name"),
            gen("uint32", "peerinfo.seed_hash", "World Seed (Hash)"),
            gen("string", "peerinfo.seed_name", "World Seed"),
            gen("int64", "peerinfo.world_id", "World ID"),
            gen("int32", "peerinfo.world_gen", "World Version"),
            gen("double", "peerinfo.world_time", "World Time")
        },
        parser = function(self, body_range, packet_info, tree, offset)
            -- skip <package> param length
            offset = offset + 4

            offset = self.fields["peerinfo.user_id"]:parser(body_range, tree, offset)
            local offset, value = self.fields["peerinfo.version"]:parser(body_range, tree, offset)
            -- >= new GameVersion(0, 214, 301);
            local has_network_version = function(other_str)
                local split = other_str:split(".")
                print(split[1], split[2], split[3])
                print(other_str)
                local ma, mi, p = tonumber(split[1]), tonumber(split[2]), tonumber(split[3])
                local MA, MI, P = 0, 214, 301

                -- 0 < 0, 214 < 200, 301 < 17
                local base = MA * 1000000 + MI * 10000 + P * 1
                local other = ma * 1000000 + mi * 10000 + p * 1

                return base <= other
            end

            local network = 0
            if has_network_version(value) then
                offset, network = self.fields["peerinfo.network_version"]:parser(body_range, tree, offset)
            end

            offset = self.fields["peerinfo.ref_pos"]:parser(body_range, tree, offset)
            offset = self.fields["peerinfo.name"]:parser(body_range, tree, offset)

            -- if server
            if packet_info.dst_port == PORT then
                --tree:append_text("C -> S")
                packet_info.cols.info:append(": C -> S")
                offset = self.fields["peerinfo.password"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.ticket"]:parser(body_range, tree, offset)
            else
                --tree:append_text("S -> C")
                packet_info.cols.info:append(": S -> C")
                offset = self.fields["peerinfo.world"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.seed_hash"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.seed_name"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.world_id"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.world_gen"]:parser(body_range, tree, offset)
                offset = self.fields["peerinfo.world_time"]:parser(body_range, tree, offset)
            end
        end
    },
    [-265949079] = {
        name = "PlayerList",
        parser = function(self, body_range, packet_info, tree, offset)
            -- TODO create container encapsulator
        end
    },
    [-667652280] = {
        name = "RoutedRpc",
        fields = compile {
            gen("int64", "routedrpc.sender", "Sender"),
            gen("int64", "routedrpc.target", "Target"),
            gen("zdoid", "routedrpc.target_zdo", "Target ZDO"),
            gen("int32", "routedrpc.method", "Method Hash")
        },
        parser = function(self, body_range, packet_info, tree, offset)
            -- skip <package> param length
            offset = offset + 4

            -- skip <routedrpc.msgid>
            offset = offset + 8

            offset = self.fields["routedrpc.sender"]:parser(body_range, tree, offset)
            offset = self.fields["routedrpc.target"]:parser(body_range, tree, offset)
            offset = self.fields["routedrpc.target_zdo"]:parser(body_range, tree, offset)
            local offset, hash = self.fields["routedrpc.method"]:parser(body_range, tree, offset)
            -- TODO map HASH / target to determine method
            -- INVOKE
            --packet_info.cols.info:append(": " .. tostring(hash))

            -- skip <param-len>
            offset = offset + 4

            --[[
                TODO this will basically be a repeat invoker of rpc
            --]]
            local routed = RoutedRpcs[hash]
            local text = routed and routed.name or ("Unknown (" .. header_result .. ")")

            if string.find(tostring(packet_info.cols.info), "^" .. NAME .. ":") == nil then
                packet_info.cols.info:append(": " .. text)
            else
                packet_info.cols.info:append(", " .. text)
            end

            -- TODO
            --  parser will be not so manual
            --  will be more arg-type declaring
            --  more simple readers for field-arguments
            if routed then
                local parser = routed.parser
                local params = routed.params

                --local offset = 0

                -- parser is parameterized
                if parser then
                    assert(not params, "'params' and 'parser' is set, is this intentional?")

                    local root1 = tree:add(proto, body_range(), text)
                    routed:parser(body_range, packet_info, root1, offset)
                else
                    -- otherwise, params is chosen if present
                    local params = routed.params
                    if params then
                        local root1 = tree:add(proto, body_range(), text)
                        for i, v in ipairs(params) do
                            offset = v:parser(body_range, root1, offset)
                        end
                    end
                end
            end
        end
    },
    [-1975616347] = {
        name = "ZDOData",
        fields = compile {
            gen("zdoid", "zdodata.id", "ZDOID"),
            gen("uint16", "zdodata.owner_rev", "Owner Rev"),
            gen("uint32", "zdodata.data_rev", "Data Rev"),
            gen("int64", "zdodata.owner", "Owner"),
            gen("vec3", "zdodata.pos", "Position"),
            --gen('uint16', 'zdodata.owner_rev', 'Owner Rev')
            --TODO sub-data members
            gen("uint16", "zdodata.flags", "Flags"),
            gen("int32", "zdodata.hash", "Prefab Hash"),
            gen("vec3", "zdodata.rot", "Rotation"),
            gen("uint8", "zdodata.conn_type", "Connection Type"),
            gen("zdoid", "zdodata.conn_target", "Connection Target"),
            --gen('uint8', 'zdodata.float_num', 'Float Count'), -- dumb
            gen("int32", "zdodata.float_hash", "Hash (Float)"), -- hmm
            gen("float", "zdodata.float_value", "Value (Float)") -- hmm
        },
        parser = function(self, body_range, packet_info, tree, offset)
            -- TODO
            --  ... list all ZDOs and their members
            --  MAYBE, in expert mode, list changed members, or somehow...

            -- skip <pkg-len>
            offset = offset + 4

            local invalid_count = body_range(offset, 4):le_int()
            offset = offset + 4 -- skip

            -- skip all read zdoids
            offset = offset + invalid_count * 12

            --local stop_count = 5

            while true do
                local root1 = tree:add(proto, body_range()) -- no text for now...

                --local root1 = tree:add(proto, body_range(), tostring(zdoid.user_id) .. ":" .. tostring(zdoid.id))

                local zdoid
                offset, zdoid = self.fields["zdodata.id"]:parser(body_range, root1, offset)

                root1:set_text("ZDO (" .. tostring(zdoid.user_id) .. ":" .. tostring(zdoid.id) .. ")")

                if zdoid.user_id == 0 and zdoid.id == 0 then
                    break
                end

                --stop_count = stop_count - 1
                --if stop_count <= 0 then
                --    break
                --end

                -- create sub-tree

                offset = self.fields["zdodata.owner_rev"]:parser(body_range, root1, offset)
                offset = self.fields["zdodata.data_rev"]:parser(body_range, root1, offset)
                offset = self.fields["zdodata.owner"]:parser(body_range, root1, offset)
                offset = self.fields["zdodata.pos"]:parser(body_range, root1, offset)

                --local offset, pkg_len = self.fields["zdodata.pos"]:parser(body_range, tree, offset)
                local pkg_len = body_range(offset, 4):le_int()
                offset = offset + 4

                --[[
                    ZDO deserialize
                --]]
                local sub_offset = offset

                -- zdodata.flags
                local flags
                sub_offset, flags = self.fields["zdodata.flags"]:parser(body_range, root1, sub_offset)

                local prefab_hash, child_tree
                sub_offset, prefab_hash, child_tree = self.fields["zdodata.hash"]:parser(body_range, root1, sub_offset)
                child_tree:append_text(": (" .. (Prefabs[prefab_hash] or "???") .. ")")
                -- append text

                sub_offset = self.fields["zdodata.rot"]:parser(body_range, root1, sub_offset)

                -- skip zdo-data parameters (tmp for now..)
                offset = offset + pkg_len
            end
        end
    },
    [-2045981424] = {
        name = "NetTime",
        params = {
            gen("double", "nettime", "Net Time")
        }
    },
    -- removed sometime after 0.217.6-public-test
    --  (functionality merged into RPC_ServerSyncedPlayerData)
    [1664081997] = {
        name = "RefPos (legacy)",
        params = {
            gen("vec3", "refpos.position", "Position"),
            gen("bool", "refpos.next_", "Next bool")
            -- forgot...
        }
    },
    [1191884308] = {
        name = "CharacterID",
        params = {
            gen("zdoid", "character_id", "Character ID")
        }
    },
    [-508691474] = {
        name = "Unban",
        params = {
            gen("string", "unban.name", "Name")
        }
    },
    [-23454927] = {
        name = "RemotePrint",
        params = {
            gen("string", "remoteprint.message", "Message")
        }
    },
    [838896224] = {
        name = "Disconnect"
        --  goodbye ¯\_(ツ)_/¯
    }
}
