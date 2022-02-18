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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dragonfang.entities.Entity;
import dragonfang.primes.maps.PrimeProductMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PrimeProductMatcher extends AbstractPrimeProductMatcher {

	public PrimeProductMatcher(PrimeProductMap srcPrimeProductMap, PrimeProductMap dstPrimeProductMap) {
		super(srcPrimeProductMap, dstPrimeProductMap);
	}

	@Override
	public Set<Match> doMatch(Set<Entity> unmatchedSrcEntitySet, Set<Entity> unmatchedDstEntitySet, TaskMonitor monitor)
			throws CancelledException {

		Set<Match> matches = new HashSet<Match>();

		HashMap<Long, List<Entity>> srcMatchMap = deriveMatchMap(unmatchedSrcEntitySet, srcPrimeProductMap, monitor);
		HashMap<Long, List<Entity>> dstMatchMap = deriveMatchMap(unmatchedDstEntitySet, dstPrimeProductMap, monitor);

		for (Entity unmatchedSrcEntity : unmatchedSrcEntitySet) {
			Long primeProduct = srcPrimeProductMap.getPrimeProduct(unmatchedSrcEntity, monitor);
			List<Entity> srcEntityList = srcMatchMap.get(primeProduct);

			if (srcEntityList.size() == 1) {
				List<Entity> dstEntityList = dstMatchMap.get(primeProduct);

				if (dstEntityList != null && dstEntityList.size() == 1) {
					double similarity = 1.0;
					double confidence = 1.0;
					Match match = new Match(unmatchedSrcEntity, dstEntityList.get(0), similarity, confidence,
							"Prime Product Matcher");
					matches.add(match);
				}
			}
		}

		return matches;
	}
}
