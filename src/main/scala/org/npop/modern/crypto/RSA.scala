package org.npop.modern.crypto

import java.security.SecureRandom
import scala.util.Random
import scala.collection.mutable.ArrayBuffer
import scala.math.{sqrt, pow, min}

object RSA extends App {

  def generateKeypair(): (Array[Byte], Array[Byte]) = ???


  private def randomN(bits: Int): BigInt = {
    val minN   = BigInt.apply(Array.fill[Byte](bits >> 1)(1))
    val random = new SecureRandom()
    val seed   = random.generateSeed(bits)
    random.setSeed(seed)
    val between = BigInt.apply(bits >> 1, new Random(random))
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

  private def candidate(bits: Int = 1024): BigInt = {
    var number = randomN(bits)
    while (!lowLevelTest(number)) {
      number = randomN(bits)
    }
    number
  }

  println(candidate())

}
