package com.tencent.demo;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct;

/**
 */
@Slf4j
@Data
@Component
public class Properties {

    private String doop = "-Dhadoop.job.ugi=abc12345:root"

}
