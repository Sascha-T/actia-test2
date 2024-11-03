current_actia = {}

usb_product_field = Field.new("usb.idProduct")
usb_vendor_field = Field.new("usb.idVendor")
usb_bus_field = Field.new("usb.bus_id")
usb_address_field = Field.new("usb.device_address")
usb_type_field = Field.new("usb.transfer_type")
usb_length_field = Field.new("usb.data_len")

actia_proto = Proto("actia", "Actia XS Evo Protocol")

command_field = ProtoField.bytes("actia.cmd", "Command")
unknown_field = ProtoField.bytes("actia.unk1", "Unknown1")
size_field = ProtoField.bytes("actia.size", "Packet Length")
flow_field = ProtoField.bytes("actia.flow_control", "Flow Control")

type_field = ProtoField.uint8("actia.type", "Command type")

c_target_field = ProtoField.bytes("actia.pc2vci.target", "VCI Command Target")
d_target_field = ProtoField.bytes("actia.vci2pc.target", "VCI Command Target")

c_command_field = ProtoField.bytes("actia.pc2vci.command", "VCI Command")
d_command_field = ProtoField.bytes("actia.vci2pc.command", "VCI Command")

c_size_field = ProtoField.uint16("actia.pc2vci.datasize", "Packet Length")
d_size_field = ProtoField.uint16("actia.vci2pc.datasize", "Packet Length")

d_unknown1_field = ProtoField.uint8("actia.vci2pc.unknown1", "Unknown1")
data_field = ProtoField.bytes("actia.data", "Data")

bad_checksum_field = ProtoExpert.new("actia.bad_checksum", "Checksum", expert.group.CHECKSUM, expert.severity.ERROR)
checksum_field = ProtoField.bytes("actia.checksum", "Checksum")


actia_proto.fields = {
	command_field, type_field, unknown_field, size_field, flow_field,
	c_target_field, d_target_field,
	c_command_field, d_command_field,
	c_size_field, d_size_field, d_unknown1_field, data_field, checksum_field
}

function _usbId()
	return tostring(usb_bus_field()) .. "." .. tostring(usb_address_field())
end

_command = {
	[0x40] = "Data PC -> VCI",
	[0x41] = "Request last status",
	[0x43] = "Request last response",
	[0x44] = "Data VCI -> PC",
	[0x42] = "Ready",
	[0x06] = "Acknowledge"
}
setmetatable(_command, {__index = function() return "unknown" end})
function appendCommand(subtree, buf, id)
	subtree:add(command_field, buf):append_text(" (".. _command[id] .. ")")
end

_vciCommand = {
	[0x09] = "Read EEPROM",
	[0x0B] = "Read Analog",
	[-6] = "Get Version",
	[0x05] = "Configuration",
	[0x04] = "Protocol (tex.)",
	[0x16] = "Protocol (bin.)"
}
setmetatable(_vciCommand, {__index = function() return "unknown" end})
function appendVciCommand(f, subtree, buf)
	subtree:add(f, buf):append_text(" (".. _vciCommand[buf:le_int(0, 1)] .. ")")
end

function actia_proto.dissector(buf, pinfo, tree)
	if usb_product_field() ~= nil then
		local name = tostring(usb_product_field()) .. tostring(usb_vendor_field())
		if name == "0xf0000x103a" then
			current_actia[_usbId()] = true
		end
	end
	if current_actia[_usbId()] ~= true then
		return 0
	end
	if usb_type_field() == nil or tostring(usb_type_field()) ~= "0x03" or tonumber(tostring(usb_length_field())) == 0 then
		return 0
	end
	
	
	
	local i = 0
	
	local packet = buf(buf(0,2):le_int())
	local command = packet:bytes():get_index(0)
	
	
	
	
	local subtree
	if command == 0x40 or command == 0x44 then
		subtree = tree:add(actia_proto, packet(0,24), "Actia Protocol Data")
		appendCommand(subtree, packet(0,1), command)
	
		subtree:add(unknown_field, packet(1,1))
		subtree:add(size_field, packet(2,1))
		subtree:add(flow_field, packet(3,1))
		i = i + 4
	
		subtree:add(type_field, 0):append_text(" (Data transfer)")
		local pc2vci = subtree:add(actia_proto, packet(i, 10), "PC2VCI")
		local vci2pc = subtree:add(actia_proto, packet(i+10, 10),"VCI2PC")
	
		pc2vci:add(c_target_field, packet(i, 1))
		appendVciCommand(c_command_field, pc2vci, packet(i+1, 1))
		local pc2vci_ds = packet(i+2, 2)
		pc2vci:add_le(c_size_field, pc2vci_ds)
		
		i = i + 10
		vci2pc:add(d_target_field, packet(i, 1))
		appendVciCommand(d_command_field, vci2pc, packet(i+1, 1))
		local vci2pc_ds = packet(i+2, 2)
		vci2pc:add_le(d_size_field, packet(i+2, 2))
		vci2pc:add_le(d_unknown1_field, packet(i+4, 1))
		
		i = i + 10
		
		local size = 0
		if command == 0x40 then
			size = pc2vci_ds:le_int(0, 2)
		else
			size = vci2pc_ds:le_int(0, 2)
		end
		
		subtree:add(data_field, packet(i, size))
		
	elseif command == 0x06 or command == 0x42 then
		subtree = tree:add(actia_proto, packet(0,3), "Actia Protocol Data")
		subtree:add(type_field, 1):append_text(" (Control flow)")
		appendCommand(subtree, packet(0,1), command)
	else
		subtree = tree:add(actia_proto, packet(0,5), "Actia Protocol Data")
		subtree:add(type_field, 2):append_text(" (Other)")
		appendCommand(subtree, packet(0,1), command)
	end
	
	local chcksum = buf(-1, 1)
	subtree:add(checksum_field, chcksum)
end

register_postdissector(actia_proto)
  