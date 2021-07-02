package helloworld;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
public class RootController {
    final DataSource dataSource;

    Logger logger = LoggerFactory.getLogger(RootController.class);

    @Autowired
    public RootController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/")
    String currentTime() throws SQLException {
        logger.info("getting connection from pool");
        try (Connection connection = this.dataSource.getConnection()) {
            ResultSet resultSet = connection.prepareStatement("SELECT now()").executeQuery();
            resultSet.next();
            return resultSet.getString(1);
        } catch (SQLException ex) {
            logger.error("failed to read current time", ex);
            throw ex;
        }
    }
}
