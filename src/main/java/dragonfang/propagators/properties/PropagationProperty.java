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

package dragonfang.propagators.properties;

import java.util.Set;

import dragonfang.entities.Entity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface PropagationProperty {

    /**
	 * Returns next set of unmatched functions to consider.
	 *
	 * @param entity          The matched entity that acts as the starting point for
	 *                        propagation.
	 * @param callGraph       The call graph of the program.
	 * @param allCandidateSet The set of unmatched candidate entities.
	 * @return
	 */
    public Set<Entity> getPropagatedEntities(Entity entity, Set<Entity> allCandidateSet,
                                             TaskMonitor monitor)
        throws CancelledException;

    /**
	 *
	 * @return The name of the propagator.
	 */
    public String getName();
}