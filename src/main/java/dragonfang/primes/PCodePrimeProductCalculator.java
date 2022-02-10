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

import dragonfang.counters.InstrCounts;
import ghidra.program.model.pcode.PcodeOp;

public class PCodePrimeProductCalculator implements InstrPrimeProductCalculator {

    @Override
    public long calculatePrimeProduct(InstrCounts instructionCounts) {

        if (PcodeOp.PCODE_MAX > Prime.array.length)
            throw new RuntimeException(
                "Not enough primes in array. We need to generate a larger one!");

        long primeProd = 1;
        for (int i = 0; i < PcodeOp.PCODE_MAX; i++) {
            if (instructionCounts.getCount(i) > 0)
                primeProd = primeProd * Prime.array[i];
        }

        return primeProd;
    }
}
