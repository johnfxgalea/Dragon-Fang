/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dragonfang.primes;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import dragonfang.counters.InstrCounts;
import dragonfang.counters.PCodeInstrCounts;
import ghidra.program.model.pcode.PcodeOp;

public class InstrPrimeProductCalculatorTest {

	@Test
	public void testPCodePrimeProductCalculator() {

		PCodePrimeProductCalculator calculator = new PCodePrimeProductCalculator();

		Set<Long> witnessedPrimes = new HashSet<Long>();
		for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
			InstrCounts instructionCounts = new PCodeInstrCounts();
			instructionCounts.incrementCount(i);
			long primeProduct = calculator.calculatePrimeProduct(instructionCounts);
			assertTrue("Prime should be unique.", !witnessedPrimes.contains(primeProduct));
			witnessedPrimes.add(primeProduct);

			BigInteger bigInt = BigInteger.valueOf(primeProduct);
			assertTrue("Prime should be prime!.", bigInt.isProbablePrime(100));
		}
	}
}
