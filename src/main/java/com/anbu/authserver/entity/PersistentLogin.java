package com.anbu.authserver.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.Date;

@Data
@Document
@Builder
public class PersistentLogin {
    @Indexed
    private String username;
    @Id
    private String series;
    private String token;
    private Date last_used;
}
