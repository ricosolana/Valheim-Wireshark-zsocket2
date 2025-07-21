local Types = assert(require("zs2_types"))
local Fields = assert(require("zs2_field_wrappers"))
local prefabs = assert(require("zs2_prefabs"))
local constants = assert(require("zs2_constants"))

local proto = Types.get_proto()

local PORT = constants.PORT

local gen = Types.generator
local compile = function(wrapper_array)
    local res = {}

    for i, wrapper in ipairs(wrapper_array) do
        res[wrapper.sub_filter_id] = wrapper
    end

    return res
end

-- https://github.com/Valheim-Modding/Wiki/wiki/RPC-Method-registrations
return {
    [-1090292557] = {
        name = "GlobalKeys",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(body_range, packet_info, tree, offset)
        end
    },
    [-1100589719] = {
        name = "LocationIcons",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(body_range, packet_info, tree, offset)
        end
    },
    [-1550530018] = {
        name = "SetEvent",
        params = {
            gen("string", "routedrpc.setevent.name", "Event Name"),
            gen("float", "routedrpc.setevent.time", "Event Time"),
            gen("string", "routedrpc.setevent.pos", "Event Position")
        }
    },
    [-1182660091] = {
        name = "ChatMessage",
        params = {
            gen("vec3", "routedrpc.chatmessage.pos", "Position"),
            gen("float", "routedrpc.chatmessage.type", "Message Type")
            --- complicated struct
            --gen("string", "routedrpc.chatmessage.userinfo", "User Info")
        },
        -- TODO add extensions / whether join-msg or ...

        dummy = 0
    },
    [-461013576] = {
        name = "Step (FootStep.cs)",
        params = {
            gen("int32", "routedrpc.step.index", "Particle Index"),
            gen("vec3", "routedrpc.step.position", "Position")
        }
    },
    [199378019] = {
        name = "DestroyZDO",
        --params = {
        --    -- TODO containerized...
        --    0
        --},
        parser = function(body_range, packet_info, tree, offset)
            --tree:add_packet_field(fields.clienthandshake_haspassword, body_range:range(offset, 1), ENC_LITTLE_ENDIAN)
            --offset = offset + 1
            --
            --offset = readers.addString(body_range, tree, "Password Salt", fields.clienthandshake_passwordsalt, offset)
        end
    }
}
