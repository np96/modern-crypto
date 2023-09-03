package org.npop.modern.crypto

import org.scalatest.funsuite.AnyFunSuite

import java.nio.charset.StandardCharsets.UTF_8


class Sha256Spec extends AnyFunSuite:


  test("hello world") {
    val result = Sha256.apply("hello world")
    assert(toHex(result) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
  }

  test("empty") {
    val result = Sha256.apply(Array.emptyByteArray)
    assert(toHex(result) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  }

  test("abc") {
    val result = Sha256.apply("abc")
    assert(toHex(result) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  }

  test("2 block string") {

    val str = "It has quickly become quite annoying to compete in meaningless midrash writing with the most successful misanthrophes"

    val result = Sha256.apply(str)

    assert(toHex(result) == "f9e5f1bb0d37f8473698100ec088ee7400f2f492a8156a88d23df9778506cf4d")
  }

  test("multi block string") {

    val str = "It has quickly become quite annoying to compete in meaningless midrash writing with the most successful misanthrophes such as rab...".repeat(4)

    val result = Sha256.apply(str)

    assert(toHex(result) == "1fa8b45cfc5fb208b2ee30a797e3217398a75f625cf72f3663520ea5c2a32430")
  }

  test("letter `a` repeated 1 million times") {
    val str = String.valueOf(Array.fill(1000000)('a'))
    val result = Sha256.apply(str)
    assert(toHex(result) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
  }

end Sha256Spec
