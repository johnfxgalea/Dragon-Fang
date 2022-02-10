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
import ghidra.program.model.listing.Function;

public interface PropagationProperty {

    /**
     * Returns next set of unmatched functions to consider.
     *
     * @param function        The matched function that acts as the starting point
     *                        for propagation.
     * @param callGraph       The call graph of the program.
     * @param allCandidateSet The set of unmatched candidate functions.
     * @return
     */
    public Set<Function> getPropagatedFuncs(Function function,
                                            Set<Function> allCandidateSet);

    /**
     *
     * @return The name of the propagator.
     */
    public String getName();
}