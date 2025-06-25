from __future__ import annotations

# Load environment before importing anything else
from dotenv import load_dotenv
load_dotenv()

from swelancer import SWELancerEval 
import argparse
import nanoeval
from nanoeval.evaluation import EvalSpec, RunnerArgs
from nanoeval.recorder import dummy_recorder
from nanoeval.setup import nanoeval_entrypoint
from swelancer_agent import SimpleAgentSolver
from pathlib import Path
import json


def parse_args():
    parser = argparse.ArgumentParser(description='Run SWELancer evaluation')
    parser.add_argument('--issue_ids', nargs='*', type=str, help='List of ISSUE_IDs to evaluate. If not specified, all issues will be evaluated.')
    parser.add_argument(
        '--adversarial_config',
        type=str,
        default=None,
        help='Path to a CSV file with adversarial prompts. Must have columns: id,adversarial_objective,prompt'
    )
    parser.add_argument(
        '--adversarial_objective_ids',
        nargs='*',
        type=str,  # Changed from int to str to match the CSV id column
        default=None,
        help='List of IDs from the adversarial_config CSV to use (based on the "id" column). If not specified, all rows will be used.'
    )
    return parser.parse_args()

async def main() -> None:
    args = parse_args()
    taskset = args.issue_ids if args.issue_ids else None

    report = await nanoeval.run(
        EvalSpec(
            eval=SWELancerEval(
                solver=SimpleAgentSolver(model="gpt-4o"),
                split="Diamond-$500k",
                taskset=taskset,
                adversarial_config=args.adversarial_config,
                adversarial_objective_ids=args.adversarial_objective_ids,
            ),
            runner=RunnerArgs(
                concurrency=25,
                experimental_use_multiprocessing=True,
                enable_slackbot=False,
                recorder=dummy_recorder(),
                max_retries=5
            ),
        )
    )
    print(report)
    Path("summary_logs").mkdir(exist_ok=True)
    with open("summary_logs/final_summary.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("Saved summary to summary_logs/final_summary.json")


if __name__ == "__main__":
    nanoeval_entrypoint(main())