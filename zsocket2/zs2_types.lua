local constants = assert(require("zs2_constants"))
local util = assert(require("zs2_util")) --str extensions

local NAME = constants.NAME
local proto  -- forward declare

local read_encoded_int = function(buffer, offset)
    local out = 0
    local num2 = 0
    while num2 ~= 35 do
        local b = buffer:range(offset, 1):le_uint()
        offset = offset + 1

        assert(b >= 0 and b <= 255, "byte too big")

        -- not supported in lua 5.2 (which Wireshark uses)
        --out |= (b & 127) << num2
        --out = out | ((b & 127) << num2)
        out = bit.bor(out, bit.lshift(bit.band(b, 127), num2))
        num2 = num2 + 7
        --if (b & 128) == 0 then
        if bit.band(b, 128) == 0 then
            return out, offset
        end
    end
    error("bad encoded int")
end

--local string_range_offset = function(buffer, offset)
--    local length, offset = read_encoded_int(buffer, offset)
--
--    return buffer:range(offset, length), offset + length
--end

local id_validate = function(id)
    assert(not id:startswith(".") and not id:endswith("."))
    return NAME .. "." .. id
end

local field_class_parser = function(wrapper, body_range, root, offset)
    for k, v in pairs(wrapper) do
        print(tostring(k) .. " ||| " .. tostring(v))
    end

    root:add_le(wrapper.field, body_range:range(offset, wrapper.size))
    return offset + wrapper.size
end

--local field_class_ctor = function(self_mapper, base)
--    local field_class = self_mapper.field_class
--    return field_class
--end

local field_class_mapper = function(field_class, size)
    return {
        field_class = field_class,
        size = size,
        parser = field_class_parser
    }
end

--[[
    what is a generator?
        the user-side builder

    what is a mapper?
        the internal memory-efficient shallow-copier
--]]
local fields_mapped = {
    --  and will be used by every rpc/route/view... -- map will contain basic type definitions
    uint8 = field_class_mapper(ProtoField.uint8, 1), -- size
    uint16 = field_class_mapper(ProtoField.uint16, 2),
    uint32 = field_class_mapper(ProtoField.uint32, 4),
    uint64 = field_class_mapper(ProtoField.uint64, 8),
    int8 = field_class_mapper(ProtoField.int8, 1), -- size
    int16 = field_class_mapper(ProtoField.int16, 2),
    int32 = field_class_mapper(ProtoField.int32, 4),
    int64 = field_class_mapper(ProtoField.int64, 8),
    float = field_class_mapper(ProtoField.float, 4),
    double = field_class_mapper(ProtoField.double, 8),
    bool = field_class_mapper(ProtoField.bool, 1),
    bytes = {
        field_class = ProtoField.bytes,
        parser = function(wrapper, body_range, root, offset)
            -- parser
            local length_range = body_range:range(offset, 4)
            local length = length_range:le_int()
            local bytes_range = body_range(offset + 4, length)

            -- Subtree
            local tree =
                root:add(proto, body_range(offset, 4 + length), wrapper.name .. " (" .. tostring(length) .. " bytes)")

            -- Ranged fields
            --tree:add_le(field_length, length_range)
            tree:add(wrapper.field, bytes_range)

            return offset + 4 + length
        end
    },
    string = {
        field_class = ProtoField.string,
        -- self is 'this' (wrapper) table
        --  mapped.string:parser(tree)
        parser = function(wrapper, body_range, root, offset)
            local length, offset_payload = read_encoded_int(body_range, offset)
            local string_range = body_range:range(offset_payload, length) --, offset + length

            --local tree = root:add(proto, body_range(offset, (offset1 - offset) + length), get_field_name(field_string) .. " (" .. string_range:string() .. ")")

            local tree =
                root:add(
                proto,
                body_range(offset, (offset_payload - offset) + length),
                wrapper.name .. " (" .. string_range:string() .. ")"
            )

            -- Encoded 7-bit (display)
            local tree_enclength =
                tree:add(proto, body_range(offset, offset_payload - offset), "Length (" .. tostring(length) .. ")")

            -- String contents (field)
            tree:add(wrapper.field, string_range) --, ENC_UTF_8 + ENC_STRING)

            return offset_payload + length
        end
    },
    zdoid = {
        field_classes = {userid = ProtoField.int64, id = ProtoField.uint32},
        --mapped_classes = {userid = }
        -- self is 'this' (wrapper) table
        --  wrapper:parser(tree)
        parser = function(wrapper, body_range, root, offset)
            local range_userid = body_range(offset, 8)
            local range_id = body_range(offset + 8, 4)

            local tree =
                root:add(
                proto,
                body_range(offset, 12),
                wrapper.name .. " (" .. tostring(range_userid:le_int64()) .. ":" .. tostring(range_id:le_uint()) .. ")"
            )

            tree:add_le(wrapper.fields.userid, range_userid)
            tree:add_le(wrapper.fields.id, range_id)

            return offset + 12
        end
    },
    vec3 = {
        field_classes = {x = ProtoField.float, y = ProtoField.float, z = ProtoField.float},
        parser = function(wrapper, body_range, root, offset)
            -- Ranges
            local x_range = body_range:range(offset + 0, 4)
            local y_range = body_range:range(offset + 4, 4)
            local z_range = body_range:range(offset + 8, 4)

            -- Subtree
            local tree =
                root:add(
                proto,
                body_range(offset, 12),
                name .. " (" .. x_range:le_float() .. ", " .. y_range:le_float() .. ", " .. z_range:le_float() .. ")"
            )

            -- Ranged fields
            tree:add_le(wrapper.fields.x, x_range)
            tree:add_le(wrapper.fields.y, y_range)
            tree:add_le(wrapper.fields.z, z_range)

            return offset + 12
        end
    },
    quat = {
        field_classes = {x = ProtoField.float, y = ProtoField.float, z = ProtoField.float, w = ProtoField.float},
        parser = function(wrapper, body_range, root, offset)
            -- Ranges
            local x_range = body_range:range(offset + 0, 4)
            local y_range = body_range:range(offset + 4, 4)
            local z_range = body_range:range(offset + 8, 4)
            local w_range = body_range:range(offset + 12, 4)

            -- Subtree
            local tree =
                root:add(
                proto,
                body_range(offset, 16),
                name ..
                    " (" ..
                        x_range:le_float() ..
                            ", " ..
                                y_range:le_float() .. ", " .. z_range:le_float() .. ", " .. w_range:le_float() .. ")"
            )

            -- Ranged fields
            tree:add_le(wrapper.fields.x, x_range)
            tree:add_le(wrapper.fields.y, y_range)
            tree:add_le(wrapper.fields.z, z_range)
            tree:add_le(wrapper.fields.z, w_range)

            return offset + 16
        end
    }
}

local _generator = function(type_key, ws_id, name, base_opt)
    local mapped = fields_mapped[type_key]

    -- to be filled out
    --local mapper_key  -- fwd
    local wrapper = {
        parser = assert(mapped.parser, 'mapped class "' .. type_key .. '" is missing a parser'),
        name = assert(name, "Must assign name to wrapper")
    }

    local field_classes = mapped.field_classes
    if field_classes then
        -- usage
        --  wrapper:parser(range, tree, offset)
        local fields = {}

        for k, field_class in pairs(field_classes) do
            local absolute_id = id_validate(ws_id .. "." .. k)
            local field = assert(field_class(absolute_id, name, base_opt))
            fields[k] = field -- trivial parser access!

            --proto.fields[ws_id .. "_" .. k] = field --field is now registered
            proto.fields[#proto.fields + 1] = field
        end

        wrapper.fields = fields
    else
        --wrapper.field = proto.fields[ws_id]
        --wrapper.field = proto.fields[ws_id]
        local field_class = assert(mapped.field_class, 'must assign a "field_class" or "field_classes"')

        local absolute_id = id_validate(ws_id)
        local field = assert(field_class(absolute_id, name, base_opt)) -- field is ctor'd

        --proto.fields[ws_id] = assert(field_class(absolute_id, name, base_opt)) --field is now registered

        -- We do not
        -- fk
        proto.fields[#proto.fields + 1] = field

        wrapper.field = field
        wrapper.size = mapped.size -- nil-nil | or value!
    end

    return wrapper
end

local _compiler = function(wrappers)
    -- registers all protos at once
    local fields = {}

    --https://stackoverflow.com/questions/75379622/how-to-add-an-array-of-fields-as-a-protofield-in-lua-dissector
    for k, field in pairs(wrappers) do
    end

    proto.fields = fields
end

--[[
usage:
    local generator = assert(require('zs2_types'))
    
    local field_wrappers = {
        clienthandshake_haspw = generator(),
        --cli... keep adding fields

        -- add all top-level readings

        -- no need for manual sub fields for encap/containerized types
    }

    wrapper = generator()
--]]
return {
    generator = _generator,
    set_proto = function(_proto)
        proto = _proto
    end,
    get_proto = function()
        return proto
    end
}
