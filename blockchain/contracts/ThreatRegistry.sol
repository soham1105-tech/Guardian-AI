// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ThreatRegistry
 * @notice Tamper-evident registry of Guardian.AI report hashes.
 *
 * Only a report's SHA-256 hash and its verdict string are stored on-chain -
 * never a URL, email body, phone number or any other personal data. Anyone can
 * recompute the hash of a report they hold and verify it here, which proves the
 * report existed at a given block timestamp and has not been altered since.
 */
contract ThreatRegistry {
    struct Report {
        bool exists;
        uint256 timestamp;
        address submitter;
        string verdict;
    }

    mapping(bytes32 => Report) private reports;

    event ReportRegistered(
        bytes32 indexed reportHash,
        address indexed submitter,
        string verdict,
        uint256 timestamp
    );

    error ReportAlreadyRegistered(bytes32 reportHash);

    /**
     * @param reportHash SHA-256 hash of the report's canonical JSON
     * @param verdict    Risk class of the report (e.g. "High Risk")
     */
    function submitReport(bytes32 reportHash, string calldata verdict) external {
        if (reports[reportHash].exists) {
            revert ReportAlreadyRegistered(reportHash);
        }

        reports[reportHash] = Report({
            exists: true,
            timestamp: block.timestamp,
            submitter: msg.sender,
            verdict: verdict
        });

        emit ReportRegistered(reportHash, msg.sender, verdict, block.timestamp);
    }

    function verifyReport(bytes32 reportHash)
        external
        view
        returns (bool exists, uint256 timestamp, address submitter, string memory verdict)
    {
        Report storage report = reports[reportHash];
        return (report.exists, report.timestamp, report.submitter, report.verdict);
    }
}
