package org.npop.modern.crypto

import Sha256.{+, |, &, ^, >>, unary_!, Init, Word32, fromInt, k, ror}

import java.nio.charset.{Charset, StandardCharsets}
import scala.collection.mutable
import scala.collection.mutable.ArraySeq

class Sha256(private val msg: Array[Byte]) {

  def digest(): Array[Byte] = {
    hash
  }

  private var h0 = fromInt(Init.h0)
  private var h1 = fromInt(Init.h1)
  private var h2 = fromInt(Init.h2)
  private var h3 = fromInt(Init.h3)
  private var h4 = fromInt(Init.h4)
  private var h5 = fromInt(Init.h5)
  private var h6 = fromInt(Init.h6)
  private var h7 = fromInt(Init.h7)

  private def toWords(bytes: Array[Byte]): Array[Word32] = {
    bytes.grouped(4).toArray
  }
  private def round(block: Array[Word32]): Unit = {
    val w = mutable.ArrayBuffer.from(
      block
    )
    w.addAll(zeros)

    for (i <- 16 to 63) {
      val s0 = ror(w(i - 15), 7) ^ ror(w(i - 15), 18) ^ (w(i - 15) >> 3)
      val s1 = ror(w(i - 2), 17) ^ ror(w(i - 2), 19) ^ (w(i - 2) >> 10)
      w(i) = w(i - 16) + s0 + w(i - 7) + s1
    }

    var (a, b, c, d, e, f, g, h) = (h0, h1, h2, h3, h4, h5, h6, h7)

    for (i <- 0 to 63) {
      val s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
      val ch = (e & f) ^ ((!e) & g)
      val temp1 = h + s1 + ch + k(i) + w(i)
      val s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
      val maj = (a & b) ^ (a & c) ^ (b & c)
      val temp2 = s0 + maj

      h = g
      g = f
      f = e
      e = d + temp1
      d = c
      c = b
      b = a
      a = temp1 + temp2
    }
    h0 += a
    h1 += b
    h2 += c
    h3 += d
    h4 += e
    h5 += f
    h6 += g
    h7 += h
  }

  private val zeros: Array[Word32] = Array.fill[Word32](48) {
    Array(0.toByte, 0.toByte, 0.toByte, 0.toByte)
  }

  private def formBlocks(): Array[Array[Byte]] = {
    val bytes  = Array.concat(msg, Array(128.toByte))
    val len    = bytes.length * 8 + 64
    val bCount = (len >> 9) + 1
    val blocks = Array.tabulate(bCount) { idx =>
      mutable.ArrayBuffer.from(
        bytes.slice(idx << 6, (idx + 1) << 6)
      )
    }
    blocks.foreach { block =>
      for (_ <- 0 until 64 - block.length) {
        block += 0.toByte
      }
    }
    val size = fromInt(msg.length * 8)
    blocks.last(60) = size(0)
    blocks.last(61) = size(1)
    blocks.last(62) = size(2)
    blocks.last(63) = size(3)

    blocks.map { _.toArray }
  }

  private val hash = {
    val b = formBlocks()

    b.foreach { b =>
      val w = toWords(b)
      round(w)
    }
    val h = mutable.ArrayBuilder.make[Byte]
    h ++= h0; h ++= h1; h ++= h2; h ++= h3
    h ++= h4; h ++= h5; h ++= h6; h ++= h7
    h.result()
  }
}

object Sha256 {
  private[Sha256] type Word32 = Array[Byte]

  private[Sha256] def _xor(a: Word32, b: Word32): Word32 = Array(
    (a(0) ^ b(0)).toByte,
    (a(1) ^ b(1)).toByte,
    (a(2) ^ b(2)).toByte,
    (a(3) ^ b(3)).toByte
  )

  private[Sha256] def _add(a: Word32, b: Word32): Word32 = {
    fromInt(
      ((Integer.toUnsignedLong(toInt(a)) + Integer.toUnsignedLong(toInt(b))) % (1L << 33)).toInt
    )
  }

  extension(w: Word32) {

    def unary_! : Word32 = Array(
      (~w(0)).toByte, (~w(1)).toByte, (~w(2)).toByte, (~w(3)).toByte
    )
    def ^(w2: Word32): Word32 = _xor(w, w2)

    def >>(n: Byte): Word32 = fromInt(toInt(w) >>> n)

    def +(w2: Word32): Word32 = _add(w, w2)

    def &(w2: Word32): Word32 = Array(
      (w(0) & w2(0)).toByte,
      (w(1) & w2(1)).toByte,
      (w(2) & w2(2)).toByte,
      (w(3) & w2(3)).toByte
    )

    def |(w2: Word32): Word32 = Array(
      (w(0) | w2(0)).toByte,
      (w(1) | w2(1)).toByte,
      (w(2) | w2(2)).toByte,
      (w(3) | w2(3)).toByte
    )
  }

  private[Sha256] def toInt(w: Word32) = {
    (w(0).toInt << 24) & 0xff000000 | (w(1).toInt << 16) & 0xff0000 | (w(2).toInt << 8) & 0xff00 | w(3).toInt & 0xff
  }

  private[Sha256] def fromInt(n: Int): Word32 = {
    val w0 = ((n & 0xff000000) >>> 24).toByte
    val w1 = ((n & 0x00ff0000) >>> 16).toByte
    val w2 = ((n & 0x0000ff00) >>> 8).toByte
    val w3 = (n & 0x000000ff).toByte
    Array(w0, w1, w2, w3)
  }

  private[Sha256] def ror(w: Word32, d: Byte): Word32 = {
    val n = toInt(w)
    fromInt(Integer.rotateRight(n, d))
  }

  def apply(str: String): Array[Byte] = apply(str.getBytes(StandardCharsets.UTF_8))

  def apply(msg: Array[Byte]): Array[Byte] = new Sha256(msg).digest()

  private[Sha256] object Init {
    val h0 = 0x6a09e667
    val h1 = 0xbb67ae85
    val h2 = 0x3c6ef372
    val h3 = 0xa54ff53a
    val h4 = 0x510e527f
    val h5 = 0x9b05688c
    val h6 = 0x1f83d9ab
    val h7 = 0x5be0cd19
  }

  private[Sha256] val k = Array(
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ).map(fromInt)

}