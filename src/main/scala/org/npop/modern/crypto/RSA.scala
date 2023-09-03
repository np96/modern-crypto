package org.npop.modern.crypto

import java.security.SecureRandom
import scala.util.Random
import scala.collection.mutable.ArrayBuffer
import scala.math.{sqrt, pow, min}

object RSA extends App {

  def generateKeypair(): (Array[Byte], Array[Byte]) = ???

  // TODO class and parameter
  val bits = 1024

  val sRandom = new SecureRandom()
  val seed = sRandom.generateSeed(bits)

  sRandom.setSeed(seed)

  val random = new Random(sRandom)


  private def randomN(bits: Int): BigInt = {
    val minN    = BigInt.apply(Array.fill[Byte](bits >> 1)(1))
    val between = BigInt.apply(bits >> 1, random)
    minN + between
  }

  /**
   *
   * @param ub upper bound, exclusive
   * @return prime numbers until ub
   */
  private def sieve(ub: Int = pow(2, 11).toInt): Seq[Int] = {
    val primes = Array.fill(ub)(true)
    primes(0) = false
    primes(1) = false
    for (i <- 2 to sqrt(ub).toInt) {
      if (primes(i)) {
        var j = i * i
        while (j < ub) {
          primes(j) = false
          j += i
        }
      }
    }
    primes.zipWithIndex
      .filter(_._1)
      .map(_._2)
  }

  private val primes = sieve()

  private def lowLevelTest(number: BigInt) = {
    primes.forall(p => number % p != 0)
  }

  private def expmod(base: BigInt, exp: BigInt, mod: BigInt): BigInt = {
    if (exp == 0) {
      1
    }
    else if (exp % 2 == 0) {
      expmod(base, exp / 2, mod).pow(2) % mod
    } else {
      (base * expmod(base, exp - 1, mod)) % mod
    }
  }

  private def trialComposite(
      tester: BigInt,
      evenComp: BigInt,
      number: BigInt,
      maxDivs: Int): Boolean = {
    if (expmod(tester, evenComp, number) == 1)
      return false
    for (i <- 0 until maxDivs) {
      if (expmod(tester, (BigInt(1) << i) * evenComp, number) == number - 1)
        return false
    }
    true
  }

  private def highLevelTest(number: BigInt): Boolean = {
    var maxDiv   = 0
    var evenComp = number - 1
    while (evenComp % 2 == 0) {
      evenComp >>= 1
      maxDiv   +=  1
    }
    val trials = 40
    for (_ <- 0 until trials) {
      // TODO verify if this is correct
      val tester = BigInt.apply(bits >> 1, random)
      if (trialComposite(tester, evenComp, number, maxDiv)) {
        return false
      }
    }
    true
  }

  private def candidate(bits: Int = 1024): BigInt = {
    var number = randomN(bits)
    while (!lowLevelTest(number) && !highLevelTest(number)) {
      number = randomN(bits)
    }
    number
  }

  println(candidate())

}
