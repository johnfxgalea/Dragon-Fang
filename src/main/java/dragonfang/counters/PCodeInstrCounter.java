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

import dragonfang.entities.Entity;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class PCodeInstrCounter implements InstrCounter {

	public InstrCounts count(Entity entity) {

		InstrCounts instrCounts = new PCodeInstrCounts();

		Program program = entity.getProgram();
		Listing listing = program.getListing();

		InstructionIterator instrIterator = listing.getInstructions(entity.getAddresses(), true);

		while (instrIterator.hasNext()) {
			Instruction instruction = instrIterator.next();
			PcodeOp[] ops = instruction.getPcode();
			for (int i = 0; i < ops.length; i++)
				instrCounts.incrementCount(ops[i].getOpcode());
		}

		return instrCounts;
	}
}
