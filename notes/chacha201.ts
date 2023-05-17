import Long from 'long'

export function chacha20_encrypt(
  key: Uint8Array,
  plain_data: Uint8Array,
  nonce: Uint8Array = new Uint8Array([
    96, 62, 33, 16, 64, 43, 102, 20, 99, 110, 113, 78, 66, 81, 98, 109, 96,
  ])
): Uint8Array {
  const counter = 0
  const block_size = 64

  // Set up the initial state based on the key and nonce
  const state = new Uint32Array([
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
    key[0],
    key[1],
    key[2],
    key[3],
    key[4],
    key[5],
    key[6],
    key[7],
    counter,
    nonce[0],
    nonce[1],
    nonce[2],
  ])

  // Convert the plain data into 64-byte blocks
  const padded_plain_data = pad_data(plain_data, block_size)
  const blocks: Array<Uint8Array> = []
  for (let i = 0; i < padded_plain_data.length; i += block_size) {
    blocks.push(padded_plain_data.subarray(i, i + block_size))
  }

  // Encrypt each block
  const encrypted_data = new Uint8Array(padded_plain_data.length)
  let encrypted_data_index = 0
  for (const block of blocks) {
    // Generate the key stream for this block
    const key_stream = chacha20_generate_key_stream(state)

    // XOR the key stream with the plain data to get the encrypted data
    const encrypted_block = new Uint8Array(block.length)
    let j = 0
    for (; j < block.length; j++) {
      encrypted_block[j] = block[j] ^ key_stream[j]
    }

    // Append the encrypted block to the encrypted data
    encrypted_data.set(encrypted_block, encrypted_data_index)
    encrypted_data_index += encrypted_block.length

    // Increment the counter in the state
    state[12] = counter + Math.floor(j / block_size)
  }

  return encrypted_data
}

export function chacha20_decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  encrypted_data: Uint8Array
): Uint8Array {
  const counter = 0
  const block_size = 64

  // Set up the initial state based on the key and nonce
  const state = new Uint32Array([
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
    key[0],
    key[1],
    key[2],
    key[3],
    key[4],
    key[5],
    key[6],
    key[7],
    counter,
    nonce[0],
    nonce[1],
    nonce[2],
  ])

  // Convert the encrypted data into 64-byte blocks
  const blocks: Array<Uint8Array> = []
  for (let i = 0; i < encrypted_data.length; i += block_size) {
    blocks.push(encrypted_data.subarray(i, i + block_size))
  }

  // Decrypt each block
  const decrypted_data = new Uint8Array(encrypted_data.length)
  let decrypted_data_index = 0
  for (const block of blocks) {
    // Generate the key stream for this block
    const key_stream = chacha20_generate_key_stream(state)

    // XOR the key stream with the encrypted data to get the decrypted data
    const decrypted_block = new Uint8Array(block.length)
    let j = 0
    for (; j < block.length; j++) {
      decrypted_block[j] = block[j] ^ key_stream[j]
    }

    // Append the decrypted block to the decrypted data
    decrypted_data.set(decrypted_block, decrypted_data_index)
    decrypted_data_index += decrypted_block.length

    // Increment the counter in the state
    state[12] = counter + Math.floor(j / block_size)
  }

  // Trim any padding from the decrypted data
  const padding_length = decrypted_data[decrypted_data.length - 1]
  return decrypted_data.subarray(0, decrypted_data.length - padding_length)
}

/**
 * @param state 长度为 16 的 Uint32Array 数组
 * @returns 长度为 64 的 Uint8Array 数组
 */
function chacha20_generate_key_stream(state: Uint32Array): Uint8Array {
  // Copy the state to a temporary array
  const temp_state = new Uint32Array(state)

  // Perform 20 rounds of quarter-round operations on the state
  for (let i = 0; i < 10; i++) {
    quarter_round(temp_state, 0, 4, 8, 12)
    quarter_round(temp_state, 1, 5, 9, 13)
    quarter_round(temp_state, 2, 6, 10, 14)
    quarter_round(temp_state, 3, 7, 11, 15)
    // console.log(temp_state)
    quarter_round(temp_state, 0, 5, 10, 15)
    quarter_round(temp_state, 1, 6, 11, 12)
    quarter_round(temp_state, 2, 7, 8, 13)
    quarter_round(temp_state, 3, 4, 9, 14)
  }
  console.log('after 20 rounds', temp_state)
  // Add the original state to the temporary array
  for (let i = 0; i < state.length; i++) {
    temp_state[i] += state[i]
  }

  // Convert the state to a byte string
  const key_stream = new Uint8Array(64)
  let key_stream_index = 0
  for (let i = 0; i < 16; i++) {
    const word = temp_state[i]
    key_stream[key_stream_index++] = word & 0xff
    key_stream[key_stream_index++] = (word >> 8) & 0xff
    key_stream[key_stream_index++] = (word >> 16) & 0xff
    key_stream[key_stream_index++] = (word >> 24) & 0xff
  }

  return key_stream
}

function quarter_round(
  state: Uint32Array,
  x: number,
  y: number,
  z: number,
  w: number
) {
  let a = new Long(state[x]),
    b = new Long(state[y]),
    c = new Long(state[z]),
    d = new Long(state[w])

  a = a.add(b).and(0xffffffff)
  d = new Long(rotate_left(d.xor(a).toNumber(), 16))

  c = c.add(d).and(0xffffffff)
  b = new Long(rotate_left(b.xor(c).toNumber(), 12))

  a = a.add(b).and(0xffffffff)
  d = new Long(rotate_left(d.xor(a).toNumber(), 8))

  c = c.add(d).and(0xffffffff)
  b = new Long(rotate_left(b.xor(c).toNumber(), 7))

  state[x] = a.and(0xffffffff).toNumber()
  state[y] = b.and(0xffffffff).toNumber()
  state[z] = c.and(0xffffffff).toNumber()
  state[w] = d.and(0xffffffff).toNumber()

  // state[x] += state[y]
  // state[w] = rotate_left(state[w] ^ state[x], 16)
  // state[z] += state[w]
  // state[y] = rotate_left(state[y] ^ state[z], 12)
  // state[x] += state[y]
  // state[w] = rotate_left(state[w] ^ state[x], 8)
  // state[z] += state[w]
  // state[y] = rotate_left(state[y] ^ state[z], 7)
}

function rotate_left(x: number, n: number): number {
  const value = new Long(x).toUnsigned().shiftLeft(n)
  const low = new Long(value.getLowBits())
  const high = new Long(value.getHighBits())
  return low.or(high).toNumber()
}

function pad_data(data: Uint8Array, block_size: number): Uint8Array {
  const padding_length = block_size - (data.length % block_size)
  const padded_data = new Uint8Array(data.length + padding_length)
  padded_data.set(data)
  padded_data.fill(padding_length, data.length)
  return padded_data
}

export function test() {
  // // let a = new Long(0x7998bfda)
  // const a = rotate_left(0x7998bfda, 7)
  // console.log(0xcc5fed3c, a)
  // console.assert(0xcc5fed3c == a, 'unsign left')
  // const key = new Uint8Array([0, 1, 2, 3, 4, 5])
  // const nonce = new Uint8Array([93, 4, 2, 5])
  // const plain = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])
  // console.log('plain', plain)
  // const enc = chacha20_encrypt(key, nonce, plain)
  // console.log('enc ', enc)
  // const dec = chacha20_decrypt(key, nonce, enc)
  // console.log('dec', dec)

  // 20
  const state = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504,
    0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    0x00000001, 0x09000000, 0x4a000000, 0x00000000,
  ])

  console.log(
    'chacha 20 generate key stream',
    chacha20_generate_key_stream(state)
  )
}

// export function test1() {
//   let a = new Long(0x11111111),
//     b = new Long(0x01020304),
//     c = new Long(0x9b8d6f43),
//     d = new Long(0x01234567)

//   a = a.add(b).and(0xffffffff)
//   d = d.xor(a)
//   d = new Long(rotate_left(d.toNumber(), 16))

//   c = c.add(d).and(0xffffffff)
//   b = b.xor(c)
//   b = new Long(rotate_left(b.toNumber(), 12))

//   a = a.add(b).and(0xffffffff)
//   d = d.xor(a)
//   d = new Long(rotate_left(d.toNumber(), 8))

//   c = c.add(d).and(0xffffffff)
//   b = b.xor(c)
//   b = new Long(rotate_left(b.toNumber(), 7))

//   console.log(a.toNumber(), b.toNumber(), c.toNumber(), d.toNumber())

//   console.assert(0xea2a92f4 === a.toNumber(), 'a')
//   console.assert(0xcb1cf8ce === b.toNumber(), 'b')
//   console.assert(0x4581472e === c.toNumber(), 'c')
//   console.assert(0x5881c4bb === d.toNumber(), 'd')
//   // console.assert(0x11111111 === a.toNumber(), 'a')
//   // console.assert(0xcc5fed3c === b.toNumber(), 'b')
//   // console.assert(0x789abcde === c.toNumber(), 'c')
//   // console.assert(0x01234567 === d.toNumber(), 'd')
// }
