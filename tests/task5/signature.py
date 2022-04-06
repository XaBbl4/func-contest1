import ed25519
import re

privKey1 = ed25519.SigningKey(open("private1.key", "rb").read())
privKey2 = ed25519.SigningKey(open("private2.key", "rb").read())

temp = open("tests5.fc.template", "r").read()

hashes = ['E107DF8F4EBE3B79F5CBD2F3A3E70B17CB64DD7E1D89B0A2F87150374FFC7497',
'B46972072D2B6828104186C5627DD83102629D8DCC8931CB7FCCE093498E80E1',
'410B9D35C43DAC7F315861DCAD040D64DCEC9B297DAEF020F0103A243E28B338'];

valid_until = '1649278500'

temp = re.sub(r'0{-valid_until-}', f'{valid_until}', temp, flags = re.M)

i = 0
for h in hashes:
	i += 1
	msg = bytes.fromhex(h);

	print(f'Message: %s' % h)

	k1_sign = privKey1.sign(msg, encoding='hex')
	k2_sign = privKey2.sign(msg, encoding='hex')

	temp = re.sub(r'0{-test%d-key1-signature1-}' % i, f'0x%s' % k1_sign[:64].decode('ascii'), temp, flags = re.M)
	temp = re.sub(r'0{-test%d-key1-signature2-}' % i, f'0x%s' % k1_sign[64:].decode('ascii'), temp, flags = re.M)
	temp = re.sub(r'0{-test%d-key2-signature1-}' % i, f'0x%s' % k2_sign[:64].decode('ascii'), temp, flags = re.M)
	temp = re.sub(r'0{-test%d-key2-signature2-}' % i, f'0x%s' % k2_sign[64:].decode('ascii'), temp, flags = re.M)

	print(f'\tk1_sign1: 0x%s' % k1_sign[:64].decode('ascii'))
	print(f'\tk1_sign2: 0x%s' % k1_sign[64:].decode('ascii'))
	print(f'\tk2_sign1: 0x%s' % k2_sign[:64].decode('ascii'))
	print(f'\tk2_sign2: 0x%s' % k2_sign[64:].decode('ascii'))

open("../tests5.fc", "w").write(temp)
