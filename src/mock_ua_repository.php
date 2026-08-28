<?php






// $data = [
//     'score_session' => 0,
//     'score_ip' => 0,
//     'access_count_session' => 0,
//     'access_count_ip' => 0,
//     'is_decreased_session' => 0,
//     'is_decreased_ip' => 0,
//     'is_no_anomaly_session' => 0,
//     'is_no_anomaly_ip' => 0
// ];

class MockUaRepository implements UaRepository {
    
    private int $scoreSession;
    private int $scoreIp;
    private int $accessCountSession;
    private int $accessCountIp;
    private int $isDecreasedSession;
    private int $isDecreasedIp;
    private int $isNoAnomalySession;
    private int $isNoAnomalyIp;


    
    public function __construct(array $data) {
        $this->scoreSession = $data['score_session'];
        $this->scoreIp = $data['score_ip'];
        $this->accessCountSession = $data['access_count_session'];
        $this->accessCountIp = $data['access_count_ip'];
        $this->isDecreasedSession = $data['is_decreased_session'];
        $this->isDecreasedIp = $data['is_decreased_ip'];
        $this->isNoAnomalySession = $data['is_no_anomaly_session'];
        $this->isNoAnomalyIp = $data['is_no_anomaly_ip'];
    }

    public function getScoreSession(): int {
        return $this->scoreSession;
    }

    public function getScoreIp(): int {
        return $this->scoreIp;
    }

    public function getAccessCountSession(): int {
        return $this->accessCountSession;
    }

    public function getAccessCountIp(): int {
        return $this->accessCountIp;
    }

    public function getIsDecreasedSession(): int {
        return $this->isDecreasedSession;
    }

    public function getIsDecreasedIp(): int {
        return $this->isDecreasedIp;
    }

    public function getIsNoAnomalySession(): int {
        return $this->isNoAnomalySession;
    }

    public function getIsNoAnomalyIp(): int {
        return $this->isNoAnomalyIp;
    }
}