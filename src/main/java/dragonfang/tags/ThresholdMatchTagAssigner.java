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

package dragonfang.tags;

public class ThresholdMatchTagAssigner implements MatchTagAssigner
{

    private final double BEST_MATCH_THRESHOLD = 1.0;
    private final double PARTIAL_MATCH_THRESHOLD = 0.5;

    @Override
    public DragonFangMatchTag assignTag(double similarity)
    {

        if (similarity >= BEST_MATCH_THRESHOLD)
            return new BestMatchTag();
        else if (similarity >= PARTIAL_MATCH_THRESHOLD)
            return new PartialMatchTag();
        else
            return new UnreliableMatchTag();
    }

    @Override
    public DragonFangMatchTag assignTag(double similarity, String reason)
    {

        if (similarity >= BEST_MATCH_THRESHOLD)
            return new BestMatchTag(reason);
        else if (similarity >= PARTIAL_MATCH_THRESHOLD)
            return new PartialMatchTag(reason);
        else
            return new UnreliableMatchTag(reason);
    }
}
