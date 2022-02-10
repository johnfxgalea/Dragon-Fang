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

package dragonfang;

import java.util.List;

import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import dragonfang.matchers.Matcher;
import dragonfang.propagators.Propagator;
import dragonfang.tags.MatchTagAssigner;

/**
 * A container class for storing useful objects for correlation, enabling data
 * dependency injection.
 */
public class DragonFangData {

    private List<Matcher> matcherList;
    private List<Propagator> propagatorList;
    private MatchTagAssigner matchTagAssigner;
    private ExtendedDirectGraphWrapper srcCallGraphWrapper;
    private ExtendedDirectGraphWrapper dstCallGraphWrapper;

    public DragonFangData(List<Matcher> matcherList,
                          List<Propagator> propagatorList,
                          MatchTagAssigner matchTagAssigner,
                          ExtendedDirectGraphWrapper srcCallGraphWrapper,
                          ExtendedDirectGraphWrapper dstCallGraphWrapper) {

        this.matcherList         = matcherList;
        this.propagatorList      = propagatorList;
        this.matchTagAssigner    = matchTagAssigner;
        this.srcCallGraphWrapper = srcCallGraphWrapper;
        this.dstCallGraphWrapper = dstCallGraphWrapper;
    }

    /**
     *
     * @return Return list of matchers used by Dragon Fang.
     */
    public List<Matcher> getMatcherList() {

        return matcherList;
    }

    /**
     *
     * @return Return list of propagators used by Dragon Fang.
     */
    public List<Propagator> getPropagatorList() {

        return propagatorList;
    }

    /**
     *
     * @return The match tag assigner used by Dragon Fang.
     */
    public MatchTagAssigner getMatchTagAssigner() {

        return matchTagAssigner;
    }

    public ExtendedDirectGraphWrapper getSourceCallGraphWrapper() {
        return srcCallGraphWrapper;
    }

    public ExtendedDirectGraphWrapper getDestinationCallGraphWrapper() {
        return dstCallGraphWrapper;
    }
}
