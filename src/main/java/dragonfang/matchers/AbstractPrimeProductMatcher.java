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

package dragonfang.matchers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import dragonfang.primes.maps.PrimeProductMap;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractPrimeProductMatcher implements Matcher{

	protected PrimeProductMap srcPrimeProductMap;
	protected PrimeProductMap dstPrimeProductMap;

	public AbstractPrimeProductMatcher(PrimeProductMap srcPrimeProductMap, PrimeProductMap dstPrimeProductMap) {

		this.srcPrimeProductMap = srcPrimeProductMap;
		this.dstPrimeProductMap = dstPrimeProductMap;
	}

	protected HashMap<Long, List<Function>> deriveMatchMap(Set<Function> unmatchedFuncSet, PrimeProductMap countMap,
			TaskMonitor monitor) throws CancelledException {

		HashMap<Long, List<Function>> matchMap = new HashMap<Long, List<Function>>();

		for (Function unmatchedFunction : unmatchedFuncSet) {
			Long primeProduct = countMap.getPrimeProduct(unmatchedFunction, monitor);

			List<Function> funcSet = matchMap.get(primeProduct);
			if (funcSet == null) {
				funcSet = new ArrayList<Function>();
				matchMap.put(primeProduct, funcSet);
			}
			funcSet.add(unmatchedFunction);
		}

		return matchMap;
	}
}
