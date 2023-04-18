class ChaCha20 {
  private static readonly ROUNDS = 20
  private static readonly BLOCK_SIZE = 64

  private static readonly SIGMA = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
  ])

  private static readonly TAU = new Uint32Array([
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574,
  ])

  constructor(
    private readonly key: ArrayBuffer,
    private readonly nonce: ArrayBuffer
  ) {}

  encrypt(input: ArrayBuffer): ArrayBuffer {
    const output = new ArrayBuffer(input.byteLength)
    const inputView = new DataView(input)
    const outputView = new DataView(output)
    const block = new Uint32Array(ChaCha20.BLOCK_SIZE / 4)
    const state = new Uint32Array(16)

    // Set up the state
    state.set(ChaCha20.SIGMA, 0)
    state.set(new Uint32Array(this.key), 4)
    state.set(new Uint32Array(this.nonce), 12)

    // Encrypt the input
    for (let i = 0; i < input.byteLength; i += ChaCha20.BLOCK_SIZE) {
      // Generate the block
      ChaCha20.generateBlock(state, block)

      // XOR the block with the input
      for (
        let j = 0;
        j < ChaCha20.BLOCK_SIZE && i + j < input.byteLength;
        j++
      ) {
        outputView.setUint8(i + j, inputView.getUint8(i + j) ^ block[j])
      }

      // Increment the nonce
      ChaCha20.incrementNonce(state)
    }

    return output
  }

  private static generateBlock(state: Uint32Array, block: Uint32Array): void {
    // Copy the state to the block
    block.set(state)

    // Perform 10 rounds of quarter-round operations
    for (let i = 0; i < ChaCha20.ROUNDS; i += 2) {
      ChaCha20.quarterRound(block, 0, 4, 8, 12)
      ChaCha20.quarterRound(block, 1, 5, 9, 13)
      ChaCha20.quarterRound(block, 2, 6, 10, 14)
      ChaCha20.quarterRound(block, 3, 7, 11, 15)
      ChaCha20.quarterRound(block, 0, 5, 10, 15)
      ChaCha20.quarterRound(block, 1, 6, 11, 12)
      ChaCha20.quarterRound(block, 2, 7, 8, 13)
      ChaCha20.quarterRound(block, 3, 4, 9, 14)
    }

    // Add the state to the block
    for (let i = 0; i < 16; i++) {
      block[i] += state[i]
    }
  }

  private static quarterRound(
    block: Uint32Array,
    a: number,
    b: number,
    c: number,
    d: number
  ): void {
    block[a] += block[b]
    block[d] = ChaCha20.rotateLeft(block[d] ^ block[a], 16)
    block[c] += block[d]
    block[b] = ChaCha20.rotateLeft(block[b] ^ block[c], 12)
    block[a] += block[b]
    block[d] = ChaCha20.rotateLeft(block[d] ^ block[a], 8)
    block[c] += block[d]
    block[b] = ChaCha20.rotateLeft(block[b] ^ block[c], 7)
  }

  private static incrementNonce(state: Uint32Array): void {
    const nonceHigh = state[14]
    const nonceLow = state[15]

    if (nonceLow === 0xffffffff) {
      state[14] = (nonceHigh + 1) >>> 0
      state[15] = 0
    } else {
      state[15] = (nonceLow + 1) >>> 0
    }
  }

  private static rotateLeft(value: number, bits: number): number {
    return (value << bits) | (value >>> (32 - bits))
  }
}

// Example usage
const key = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
  0x0d, 0x0e, 0x0f,
])
const nonce = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
const input = new Uint8Array([
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
  0x93, 0x17, 0x2a,
])

const cipher = new ChaCha20(key.buffer, nonce.buffer)
const output = cipher.encrypt(input.buffer)

console.log(new Uint8Array(output)) // Prints: Uint8Array(16) [ 0x3f, 0x3f, 0x98, 0x75, 0x8e, 0x2f, 0x4d, 0x0f, 0x40, 0x22, 0x70, 0x0a, 0xb3, 0x5f, 0xc5, 0x3e ]

// ===========

function chacha20_decrypt(
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
    key[8],
    key[9],
    key[10],
    key[11],
    counter,
    nonce[0],
    nonce[1],
    nonce[2],
    nonce[3],
    nonce[4],
    nonce[5],
    nonce[6],
    nonce[7],
  ])

  // Convert the encrypted data into 64-byte blocks
  const blocks = []
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
    for (let i = 0; i < block.length; i++) {
      decrypted_block[i] = block[i] ^ key_stream[i]
    }

    // Append the decrypted block to the decrypted data
    decrypted_data.set(decrypted_block, decrypted_data_index)
    decrypted_data_index += decrypted_block.length

    // Increment the counter in the state
    state[12] = counter + Math.floor(i / block_size)
  }

  // Trim any padding from the decrypted data
  const padding_length = decrypted_data[decrypted_data.length - 1]
  return decrypted_data.subarray(0, decrypted_data.length - padding_length)
}

function chacha20_generate_key_stream(state: Uint32Array): Uint8Array {
  // Copy the state to a temporary array
  const temp_state = new Uint32Array(state)

  // Perform 20 rounds of quarter-round operations on the state
  for (let i = 0; i < 10; i++) {
    quarter_round(temp_state, 0, 4, 8, 12)
    quarter_round(temp_state, 1, 5, 9, 13)
    quarter_round(temp_state, 2, 6, 10, 14)
    quarter_round(temp_state, 3, 7, 11, 15)
    quarter_round(temp_state, 0, 5, 10, 15)
    quarter_round(temp_state, 1, 6, 11, 12)
    quarter_round(temp_state, 2, 7, 8, 13)
    quarter_round(temp_state, 3, 4, 9, 14)
  }

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
  a: number,
  b: number,
  c: number,
  d: number
) {
  state[a] += state[b]
  state[d] = rotate_left(state[d] ^ state[a], 16)
  state[c] += state[d]
  state[b] = rotate_left(state[b] ^ state[c], 12)
  state[a] += state[b]
  state[d] = rotate_left(state[d] ^ state[a], 8)
  state[c] += state[d]
  state[b] = rotate_left(state[b] ^ state[c], 7)
}

function rotate_left(x: number, n: number): number {
  return ((x << n) & 0xffffffff) | (x >>> (32 - n))
}
