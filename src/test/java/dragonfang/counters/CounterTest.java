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

package dragonfang.counters;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

public class CounterTest extends AbstractDragonFangTest {

	@Test
	public void testPCodeInstrCounterXOR() {

		Function simpleFunction = getSimpleFunction(builder);

		PCodeInstrCounter instrCounter = new PCodeInstrCounter();
		InstrCounts counts = instrCounter.count(simpleFunction);
		assertEquals("Count should be 0.", 0, counts.getCount(PcodeOp.BOOL_XOR));
	}

	@Test
	public void testPCodeInstrCounterCALLIND() {

		Function simpleFunction = getSimpleFunction(builder);

		PCodeInstrCounter instrCounter = new PCodeInstrCounter();
		InstrCounts counts = instrCounter.count(simpleFunction);
		assertEquals("Count should be 2.", 2, counts.getCount(PcodeOp.CALLIND));
	}

	@Test
	public void testPCodeInstrCounterCopy() {

		Function simpleFunction = getSimpleFunction(builder);

		PCodeInstrCounter instrCounter = new PCodeInstrCounter();
		InstrCounts counts = instrCounter.count(simpleFunction);
		assertEquals("Count should be 18.", 18, counts.getCount(PcodeOp.COPY));
	}
}
