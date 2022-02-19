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

package dragonfang.propagators;

import java.util.Set;

import dragonfang.matchers.Match;
import dragonfang.matchers.Matcher;
import dragonfang.propagators.properties.PropagationProperty;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PropertyBasedPropagator implements Propagator
{

    private PropagationProperty srcProperty;
    private PropagationProperty dstProperty;

    public PropertyBasedPropagator(PropagationProperty srcProperty,
                                   PropagationProperty dstProperty)
    {
        this.srcProperty = srcProperty;
        this.dstProperty = dstProperty;
    }

    public Set<Match> propagate(Matcher matcher, Match match,
                                Set<Function> unmatchedSrcFuncSet,
                                Set<Function> unmatchedDstFuncSet, TaskMonitor monitor)
        throws CancelledException
    {

        Function srcMatchedFunction = match.getSourceFunction();
        Function dstMatchedFunction = match.getDestinationFunction();

        Set<Function> limitedUnmatchedSrcFuncSet =
            srcProperty.getPropagatedFuncs(srcMatchedFunction, unmatchedSrcFuncSet);
        Set<Function> limitedUnmatchedDstFuncSet =
            dstProperty.getPropagatedFuncs(dstMatchedFunction, unmatchedDstFuncSet);

        Set<Match> matches = matcher.doMatch(limitedUnmatchedSrcFuncSet,
                                             limitedUnmatchedDstFuncSet, monitor);

        for (Match propMatch : matches)
            propMatch.setPropagatorName(srcProperty.getName());

        return matches;
    }
}
