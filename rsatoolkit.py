import os, sys
from rsawienerattack import *
from optparse import OptionParser, OptionGroup
from Crypto.PublicKey import RSA
from Crypto import Random
import gmpy
import base64
import numpy

def victory(rsa):
	print "Private key recovered"
	print rsa.exportKey('PEM')
	sys.exit(None)

def primes(n):
	""" Input n>=6, Returns a array of primes, 2 <= p < n """
	# http://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n/3035188#3035188
	sieve = numpy.ones(n/3 + (n%6==2), dtype=numpy.bool)
	for i in xrange(1,int(n**0.5)/3+1):
		if sieve[i]:
			k=3*i+1|1
			sieve[k*k/3::2*k] = False
			sieve[k*(k-2*(i&1)+4)/3::2*k] = False
	return numpy.r_[2,3,((3*numpy.nonzero(sieve)[0][1:]+1)|1)]

if __name__ == "__main__":
	parser = OptionParser(description="Attempt to reconstruct the private key from known (and unknown) RSA parameters. Several attacks are tried against they key material.")

	material = OptionGroup(parser, "Key material", "Supply known RSA key material")
	material.add_option("-N", "--modulus", type=long, metavar="0x1234..", dest="N", help="Modulus (N)")
	material.add_option("-e", "--public_exponent", type=long, metavar="65537", dest="e", help="Public exponent (e)")
	material.add_option("-d", "--private_exponent", type=long, metavar="0x2345..", dest="d", help="Private exponent (d)")
	material.add_option("-p", "--prime_p", type=long, metavar="0x3456..", dest="p", help="Prime number 1 (p)")
	material.add_option("-q", "--prime_q", type=long, metavar="0x4567..", dest="q", help="Prime number 2 (q)")
	parser.add_option_group(material)	

	attacks = OptionGroup(parser, "Attacks", "Attempt specific attack, or hail Mary")
	attacks.add_option("-a", "--auto", action="store_true", default=True, dest="automode", help="Try to recover key material automatically by executing relevant attacks/maths. (Default)")
	attacks.add_option("--wiener", action="store_true", default=False, dest="wiener", help="Try the Wiener attack. Needs at least N, and preferrably e.")
	parser.add_option_group(attacks)

	general = OptionGroup(parser, "General", "General options")
	general.add_option("--outfile", dest="outfile", help="Output file (prefix) to which the key data is written to.")
	general.add_option("--no-outfile", action="store_true", default=False, dest="nooutfile", help="By default, we save your key data anyway, since you're sloppy.")
	parser.add_option_group(general)

	(opt, args) = parser.parse_args()

	if opt.outfile is not None and opt.nooutfile:
		sys.exit("Option parser: --outfile and --no-outfile cannot be used together.")

	if opt.N is not None and opt.e is not None and opt.d is not None:
		rsa = RSA.construct((opt.N, opt.e, opt.d))
		victory(rsa)

	if opt.N is not None and opt.e is None and opt.d is not None:
		print "Got N and d, we still need e."
		print "Will attempt to brute force the value of e."

		def attempt_e(list):
			for e in list:
				try:
					rsa = RSA.construct((opt.N, long(e), opt.d))
				except ValueError:
					continue
				if rsa is not None:
					print "Successful with e=%lu" % long(e)
					victory(rsa)

		print " - Attempting common values e=3 and e=65537"
		attempt_e([65537, 3])

		print " - No go, bruting our way from e=2 to e=65536"
		attempt_e(range(2, 65537))
		
#	if opt.prime_p is not None and opt.prime_q is not None:
#		N = opt.prime_p 

	wiener_attack(1,1)
