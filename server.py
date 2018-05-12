import asyncio
import logging
import struct

logging.basicConfig(level=logging.DEBUG)

BUF_SIZE = 64 * 1024

class BadData(Exception):
	pass

class NoAcceptMethod(Exception):
	pass

class Server(object):
	def __init__(self, reader, writer):
		self.reader = reader
		self.writer = writer

	async def run(self):
		data = await self.reader.read(1024)
		logging.debug("Received data:{0}".format(data))
		self._check_auth_method(data)
		self.writer.write(b"\x05\x00")
		data = await self.reader.read(1024)
		logging.debug("Received data:{0}".format(data))
		ver, cmd, rsv, atyp = struct.unpack("BBBB", data[0:4])
		logging.debug("ver:{0}, cmd:{1}, rsv:{2}, atyp:{3}".format(ver, cmd, rsv, atyp))
		if ver != 5 or rsv != 0:
			logging.debug("wrong ver:{0} or rsv:{1}".format(ver, rsv))
			raise BadData

	def _check_auth_method(self, data):
		if len(data) < 3:
			logging.warning("method header is too short")
			raise BadData
		ver, nmethods = struct.unpack("BB", data[0:2])
		if ver != 5:
			logging.warning("version is not 5")
			raise BadData
		if nmethods < 1:
			logging.warning("nmethods must >= 1")
			raise BadData
		noauth_exist = False
		for method in data[2:]:
			if method == 0x00:
				noauth_exist = True

		if not noauth_exist:
			logging.warning("no NOAUTH_METHOD exists")
			raise NoAcceptMethod
		logging.debug("version:{0}, nmethods:{1}".format(ver, nmethods))

async def handle_echo(reader, writer):
	try:
		server = Server(reader, writer)
		await server.run()
	except NoAcceptMethod:
		await self.writer(b"\x05\xFF")
	except:
		raise
	finally:
		logging.debug("close socket")
		writer.close()

loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, '0.0.0.0', 8888, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
