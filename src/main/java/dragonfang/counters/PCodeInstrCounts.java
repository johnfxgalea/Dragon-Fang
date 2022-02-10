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

import ghidra.program.model.pcode.PcodeOp;

public class PCodeInstrCounts implements InstrCounts {

    int count[];

    public PCodeInstrCounts() {
        count = new int[PcodeOp.PCODE_MAX];
    }

    public void incrementCount(int pcodeOpcode) {
        if (pcodeOpcode < 0 || pcodeOpcode > PcodeOp.PCODE_MAX)
            throw new IllegalArgumentException(
                "Invalid Pcode Opcode index passed as param.");

        count[pcodeOpcode]++;
    }

    public void decrementCount(int pcodeOpcode) {
        if (pcodeOpcode < 0 || pcodeOpcode > PcodeOp.PCODE_MAX)
            throw new IllegalArgumentException(
                "Invalid Pcode Opcode index passed as param.");

        count[pcodeOpcode]--;
    }

    public int getCount(int pcodeOpcode) {
        if (pcodeOpcode < 0 || pcodeOpcode > PcodeOp.PCODE_MAX)
            throw new IllegalArgumentException(
                "Invalid Pcode Opcode index passed as param.");

        return count[pcodeOpcode];
    }
}
