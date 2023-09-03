package org.npop.modern

package object crypto {

  def toHex(bytes: Array[Byte]) = {
    val sb = new StringBuilder
    for (b <- bytes) {
      sb.append(String.format("%02x", Byte.box(b)))
    }
    sb.toString()
  }

  def toBinary(bytes: Array[Byte]) = {
    val sb = new StringBuilder
    for (b <- bytes) {
      sb.append(String.format("%8s", Integer.toBinaryString(Byte.box(b) & 0xFF)).replace(' ', '0'))
    }
    sb.toString()
  }

  def prettify(hexOrBinary: String) = {
    val sb = new StringBuilder
    for (s <- hexOrBinary.grouped(8)) {
      sb.append(s)
      sb.append(" ")
    }
    sb.toString()
  }

}
