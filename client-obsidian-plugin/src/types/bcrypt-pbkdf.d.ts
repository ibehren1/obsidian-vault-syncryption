declare module "bcrypt-pbkdf" {
	/** OpenBSD bcrypt_pbkdf. Writes `keylen` bytes into `key`. Returns 0 on success, -1 on bad input. */
	export function pbkdf(
		pass: Uint8Array,
		passlen: number,
		salt: Uint8Array,
		saltlen: number,
		key: Uint8Array,
		keylen: number,
		rounds: number,
	): number;
}
