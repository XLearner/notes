async function encryptAES(
  data: string,
  key: Uint8Array,
  iv: Uint8Array
): Promise<string> {
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false,
    ['encrypt']
  )
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    new TextEncoder().encode(data)
  )
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}

async function decryptAES(
  data: string,
  key: Uint8Array,
  iv: Uint8Array
): Promise<string> {
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    { name: 'AES-CBC' },
    false,
    ['decrypt']
  )
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    new Uint8Array(
      atob(data)
        .split('')
        .map((c) => c.charCodeAt(0))
    )
  )
  return new TextDecoder().decode(decrypted)
}

// 使用示例
const key = new Uint8Array([
  /* your 32-byte key here */
])
const iv = new Uint8Array([
  /* your 16-byte IV here */
])
const data = 'Hello, world!'

encryptAES(data, key, iv).then((encrypted) => {
  console.log('Encrypted:', encrypted)
})

decryptAES(encrypted, key, iv).then((decrypted) => {
  console.log('Decrypted:', decrypted)
})
