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

import java.util.Set;

import dragonfang.entities.Entity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The interface of a matcher aims to be very straight-forward. Given two set of source
 * and destination functions, a matcher returns a set of matches.
 */
public interface Matcher {

    /**
     * Performs function matching.
     *
     * @param unmatchedSrcEntitySet Set of unmatched entities of the source program.
     * @param unmatchedDstEntitySet Set of unmatched entities of the destination program.
     * @param monitor
     * @return Set of found matches.
     * @throws CancelledException
     */
    public Set<Match> doMatch(Set<Entity> unmatchedSrcEntitySet,
                              Set<Entity> unmatchedDstEntitySet,
                              TaskMonitor monitor) throws CancelledException;
}
