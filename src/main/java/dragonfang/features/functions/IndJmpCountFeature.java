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

package dragonfang.features.functions;

import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counters.InstrCounts;
import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import dragonfang.features.Feature;
import dragonfang.features.FunctionFeature;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class IndJmpCountFeature extends FunctionFeature {

    private InstrCountMap instrCountMap;

    public IndJmpCountFeature(InstrCountMap instrCountMap) {
        this.instrCountMap = instrCountMap;
    }

    @Override
    public double calculateFeatureValue(Entity entity, TaskMonitor monitor)
        throws CancelledException {

    	if (!isEntityValid(entity))
			throw new IllegalArgumentException("Invalid entity.");
    	
		FunctionEntity functionEntity = (FunctionEntity) entity;
		
        InstrCounts instrCounts = instrCountMap.getInstructionCounts(functionEntity.getFunction(), monitor);
        double numCalls         = instrCounts.getCount(PcodeOp.BRANCHIND);

        return numCalls;
    }
}