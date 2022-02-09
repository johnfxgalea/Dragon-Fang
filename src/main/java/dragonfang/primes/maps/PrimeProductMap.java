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

package dragonfang.primes.maps;

import java.util.HashMap;
import java.util.Map;

import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counters.InstrCounts;
import dragonfang.primes.InstrPrimeProductCalculator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PrimeProductMap implements PrimeMap {

	private InstrPrimeProductCalculator primeProductCalculator;
	private Map<Function, Long> primeMap;
	private InstrCountMap countMap;

	public PrimeProductMap(InstrPrimeProductCalculator primeProduct, InstrCountMap countMap) {

		this.primeProductCalculator = primeProduct;
		this.countMap = countMap;
		this.primeMap = new HashMap<Function, Long>();
	}

	public Long getPrimeProduct(Function function, TaskMonitor monitor) throws CancelledException {

		if (!primeMap.containsKey(function)) {
			InstrCounts instrCounts = countMap.getInstructionCounts(function, monitor);
			Long primeProduct = primeProductCalculator.calculatePrimeProduct(instrCounts);
			primeMap.put(function, primeProduct);
		}

		return primeMap.get(function);
	}
}
