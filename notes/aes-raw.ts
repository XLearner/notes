/* 
  1、密钥扩展：将输入的密钥扩展为多个轮密钥。这个过程会生成一系列的轮密钥，每个轮密钥用于加密一个数据块。

  2、初始转换：将输入的数据块转换为状态矩阵。为了方便计算，AES 将输入数据块看成一个 4x4 的矩阵，其中每个元素是一个字节。

  3、轮操作：对状态矩阵执行一系列的轮操作，包括字节代换、行移位、列混淆和轮密钥加。这些操作会改变状态矩阵的值，从而使得加密后的数据更加难以被破解。
    // 根据密钥轮密钥矩阵，对状态进行一系列操作，包括字节代换、行位移、列混淆和轮密钥加等，这些操作被称为一轮。根据密钥的长度，需要执行10轮、12轮或14轮。

  4、最终转换：在执行完最后一轮操作后，将状态矩阵转换为输出的密文。这个过程与初始转换相反，即将 4x4 的矩阵转换为一个长度为 16 字节的数据块。
    // 最后一轮操作后，将状态转换为输出的密文。将状态矩阵按列优先的顺序转换为16个字节，即为输出的密文。

  5、解密时，需要使用相同的密钥和初始向量（IV），并按照相反的顺序执行加密算法中的操作。
 */

function encryptAES(data: string, key: Uint8Array, iv: Uint8Array): string {
  const blockSize = 16
  const paddedData = padData(data, blockSize)
  const aes = new AES(key)
  const encrypted = aes.encrypt(paddedData, iv)
  return bytesToBase64(encrypted)
}

function decryptAES(data: string, key: Uint8Array, iv: Uint8Array): string {
  const blockSize = 16
  const encrypted = base64ToBytes(data)
  const aes = new AES(key)
  const decrypted = aes.decrypt(encrypted, iv)
  return unpadData(decrypted, blockSize)
}

function padData(data: string, blockSize: number): Uint8Array {
  const padding = blockSize - (data.length % blockSize)
  const paddedData = new Uint8Array(data.length + padding)
  paddedData.set(new TextEncoder().encode(data))
  paddedData.fill(padding, data.length)
  return paddedData
}

function unpadData(data: Uint8Array, blockSize: number): string {
  const padding = data[data.length - 1]
  if (padding < 1 || padding > blockSize) {
    throw new Error('Invalid padding')
  }
  for (let i = data.length - padding; i < data.length; i++) {
    if (data[i] !== padding) {
      throw new Error('Invalid padding')
    }
  }
  return new TextDecoder().decode(data.subarray(0, data.length - padding))
}

function bytesToBase64(bytes: Uint8Array): string {
  let base64 = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]
    const b = bytes[i + 1]
    const c = bytes[i + 2]
    const b1 = (a >> 2) & 0x3f
    const b2 = ((a & 0x3) << 4) | ((b >> 4) & 0xf)
    const b3 = ((b & 0xf) << 2) | ((c >> 6) & 0x3)
    const b4 = c & 0x3f
    base64 +=
      base64Chars[b1] +
      base64Chars[b2] +
      (b == 0 ? '=' : base64Chars[b3]) +
      (c == 0 ? '=' : base64Chars[b4])
  }
  return base64
}

function base64ToBytes(base64: string): Uint8Array {
  const bytes = new Uint8Array((base64.length * 3) / 4)
  let i = 0
  let j = 0
  while (i < base64.length) {
    const b1 = base64Chars.indexOf(base64[i++])
    const b2 = base64Chars.indexOf(base64[i++])
    const b3 = base64Chars.indexOf(base64[i++])
    const b4 = base64Chars.indexOf(base64[i++])
    const a = ((b1 & 0x3f) << 2) | ((b2 >> 4) & 0x3)
    const b = ((b2 & 0xf) << 4) | ((b3 >> 2) & 0xf)
    const c = ((b3 & 0x3) << 6) | (b4 & 0x3f)
    bytes[j++] = a
    if (b != 0) {
      bytes[j++] = b
    }
    if (c != 0) {
      bytes[j++] = c
    }
  }
  return bytes
}

const base64Chars =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

class AES {
  private key: Uint8Array

  constructor(key: Uint8Array) {
    if (![16, 24, 32].includes(key.length)) {
      throw new Error('Invalid key size')
    }
    this.key = key
  }

  public encrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
    const blockSize = 16
    const numBlocks = Math.ceil(data.length / blockSize)
    const encrypted = new Uint8Array(numBlocks * blockSize)
    const aes = this.createAES(iv)
    for (let i = 0; i < numBlocks; i++) {
      const block = data.subarray(i * blockSize, (i + 1) * blockSize)
      const encryptedBlock = aes.encryptBlock(block)
      encrypted.set(encryptedBlock, i * blockSize)
    }
    return encrypted
  }

  public decrypt(data: Uint8Array, iv: Uint8Array): Uint8Array {
    const blockSize = 16
    const numBlocks = data.length / blockSize
    const decrypted = new Uint8Array(numBlocks * blockSize)
    const aes = this.createAES(iv)
    for (let i = 0; i < numBlocks; i++) {
      const block = data.subarray(i * blockSize, (i + 1) * blockSize)
      const decryptedBlock = aes.decryptBlock(block)
      decrypted.set(decryptedBlock, i * blockSize)
    }
    return decrypted
  }

  private createAES(iv: Uint8Array): AESImpl {
    const keySize = this.key.length / 4
    const aes = new AESImpl(keySize)
    aes.setKey(this.key)
    aes.setIV(iv)
    return aes
  }
}

class AESImpl {
  private keySize: number
  private key: Uint32Array
  private iv: Uint32Array

  constructor(keySize: number) {
    this.keySize = keySize
    this.key = new Uint32Array(keySize * 4)
    this.iv = new Uint32Array(4)
  }

  public setKey(key: Uint8Array) {
    if (key.length !== this.keySize * 4) {
      throw new Error('Invalid key size')
    }
    for (let i = 0; i < this.keySize; i++) {
      this.key[i * 4] =
        (key[i * 4] << 24) |
        (key[i * 4 + 1] << 16) |
        (key[i * 4 + 2] << 8) |
        key[i * 4 + 3]
    }
    this.expandKey()
  }

  public setIV(iv: Uint8Array) {
    if (iv.length !== 16) {
      throw new Error('Invalid IV size')
    }
    this.iv[0] = (iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3]
    this.iv[1] = (iv[4] << 24) | (iv[5] << 16) | (iv[6] << 8) | iv[7]
    this.iv[2] = (iv[8] << 24) | (iv[9] << 16) | (iv[10] << 8) | iv[11]
    this.iv[3] = (iv[12] << 24) | (iv[13] << 16) | (iv[14] << 8) | iv[15]
  }

  public encryptBlock(block: Uint8Array): Uint8Array {
    if (block.length !== 16) {
      throw new Error('Invalid block size')
    }
    const state = new Uint32Array(4)
    state[0] = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]
    state[1] = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]
    state[2] =
      (block[8] << 24) | (block[9] << 16) | (block[10] << 8) | block[11]
    state[3] =
      (block[12] << 24) | (block[13] << 16) | (block[14] << 8) | block[15]
    this.addRoundKey(state, 0)
    for (let i = 1; i < this.keySize; i++) {
      this.subBytes(state)
      this.shiftRows(state)
      this.mixColumns(state)
      this.addRoundKey(state, i)
    }
    this.subBytes(state)
    this.shiftRows(state)
    this.addRoundKey(state, this.keySize)
    const encrypted = new Uint8Array(16)
    encrypted[0] = (state[0] >>> 24) & 0xff
    encrypted[1] = (state[0] >>> 16) & 0xff
    encrypted[2] = (state[0] >>> 8) & 0xff
    encrypted[3] = state[0] & 0xff
    encrypted[4] = (state[1] >>> 24) & 0xff
    encrypted[5] = (state[1] >>> 16) & 0xff
    encrypted[6] = (state[1] >>> 8) & 0xff
    encrypted[7] = state[1] & 0xff
    encrypted[8] = (state[2] >>> 24) & 0xff
    encrypted
  }
}
