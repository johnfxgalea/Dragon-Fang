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

/**
 *
 * Performs match propagation based on call graph properties.
 */
public abstract class AbstractPropagationProperty implements PropagationProperty
{

    protected Set<Entity> processCandidates(Set<Entity> propEntitySet,
                                            Set<Entity> allCandidateSet)
    {

        propEntitySet.retainAll(allCandidateSet);
        return propEntitySet;
    }
}
