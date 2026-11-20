package com.tanvi.auth.service;

import com.tanvi.auth.domain.SecurityEvent;
import com.tanvi.auth.domain.User;
import com.tanvi.auth.repository.SecurityEventRepository;
import com.tanvi.auth.security.ClientInfo;
import com.tanvi.auth.web.dto.AccountDtos.EventResponse;
import com.tanvi.auth.web.dto.AccountDtos.PageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Writes and reads the security audit log. Each event is also logged, for log-based alerting. */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("security.audit");

    private final SecurityEventRepository events;

    public AuditService(SecurityEventRepository events) {
        this.events = events;
    }

    @Transactional
    public void record(SecurityEvent.Type type, User user, ClientInfo client, String detail) {
        record(type, user == null ? null : user.getId(), user == null ? null : user.getUsername(), null, client, detail);
    }

    @Transactional
    public void record(SecurityEvent.Type type, Long userId, String username, String actor, ClientInfo client,
                       String detail) {
        events.save(new SecurityEvent(type, userId, username, actor, client == null ? null : client.ip(), detail));
        log.info("{} user={} actor={} ip={} {}", type, username, actor, client == null ? "-" : client.ip(),
                detail == null ? "" : detail);
    }

    @Transactional(readOnly = true)
    public List<EventResponse> forUser(Long userId) {
        return events.findTop20ByUserIdOrderByOccurredAtDescIdDesc(userId).stream().map(EventResponse::from).toList();
    }

    @Transactional(readOnly = true)
    public PageResponse<EventResponse> list(SecurityEvent.Type type, int page, int size) {
        PageRequest pageable = PageRequest.of(Math.max(0, page), Math.clamp(size, 1, 100),
                Sort.by(Sort.Direction.DESC, "occurredAt", "id"));
        var result = type == null ? events.findAll(pageable) : events.findByType(type, pageable);
        return PageResponse.from(result.map(EventResponse::from));
    }
}
