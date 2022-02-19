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

import static org.junit.Assert.*;
import org.junit.Test;

import ghidra.program.model.pcode.PcodeOp;

public class CountTest
{

    @Test
    public void testInit()
    {

        InstrCounts count = new PCodeInstrCounts();
        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            int countVal = count.getCount(i);
            assertEquals("Must be initialised to 0.", 0, countVal);
        }
    }

    @Test
    public void testIncrement()
    {

        InstrCounts count = new PCodeInstrCounts();
        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            count.incrementCount(i);
        }

        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            int countVal = count.getCount(i);
            assertEquals("After increment, count value should be 1.", 1, countVal);
        }
    }

    @Test
    public void testIncrement2()
    {

        InstrCounts count = new PCodeInstrCounts();
        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            count.incrementCount(i);
            count.incrementCount(i);
        }

        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            int countVal = count.getCount(i);
            assertEquals("After two increment, count value should be 2.", 2, countVal);
        }
    }

    @Test
    public void testDecrement()
    {

        InstrCounts count = new PCodeInstrCounts();
        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            count.incrementCount(i);
        }

        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            count.decrementCount(i);
        }

        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            int countVal = count.getCount(i);
            assertEquals("After decrement, count value should be 0.", 0, countVal);
        }
    }
}
