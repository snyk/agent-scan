from agent_scan.inspect import inspected_client_to_scan_path_result
from agent_scan.models import (
    AnalysisError,
    AnalyzedMachine,
    ClientAnalysis,
    InspectedMachine,
    NewIssue,
)
from agent_scan.verify_api import analyze_machine as analyze_scan_path_results


async def analyze_machine(
    machine: InspectedMachine,
    analysis_url: str,
    identifier: str | None,
    additional_headers: dict | None = None,
    opt_out_of_identity: bool = False,
    verbose: bool = False,
    skip_pushing: bool = False,
    push_key: str | None = None,
    max_retries: int = 3,
    skip_ssl_verify: bool = False,
) -> AnalyzedMachine:
    scan_path_results = [inspected_client_to_scan_path_result(inspected_client) for inspected_client in machine.clients]
    try:
        analyzed_scan_path_results = await analyze_scan_path_results(
            scan_path_results,
            analysis_url=analysis_url,
            identifier=identifier,
            additional_headers=additional_headers,
            opt_out_of_identity=opt_out_of_identity,
            verbose=verbose,
            skip_pushing=skip_pushing,
            push_key=push_key,
            max_retries=max_retries,
            skip_ssl_verify=skip_ssl_verify,
        )
    except Exception as e:
        return AnalyzedMachine(
            machine=machine,
            analysis=AnalysisError(
                message=str(e),
                traceback=None,
                is_failure=True,
                category="analysis_error",
            ),
        )

    analyzed_machine = AnalyzedMachine(clients=[])
    for _, analyzed_scan_path_result in zip(machine.clients, analyzed_scan_path_results, strict=True):
        new_issues: list[NewIssue] = []
        reference_map: dict[
            tuple[int, int | None],
            tuple[tuple[str, int], int | None],
        ] = {}

        for issue in analyzed_scan_path_result.issues:
            new_issues.append(
                NewIssue(
                    code=issue.code,
                    message=issue.message,
                    reference=reference_map[issue.reference] if issue.reference is not None else None,
                    extra_data=issue.extra_data,
                )
            )
        analysis = ClientAnalysis(
            labels=analyzed_scan_path_result.labels,
            issues=analyzed_scan_path_result.issues,
        )
        analyzed_machine.analysis.append(analysis)
    return analyzed_machine
