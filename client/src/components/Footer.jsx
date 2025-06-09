import { Container, Row, Col } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faFacebook,
  faTwitter,
  faInstagram,
  faGithub,
} from '@fortawesome/free-brands-svg-icons';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-dark text-light py-4 mt-auto">
      <Container>
        <Row className="g-4">
          {/* 關於我們 */}
          <Col md={4}>
            <h5 className="mb-3">關於我們</h5>
            <p className="text-muted">
              我們致力於提供最好的用戶體驗和服務。無論您有任何問題或建議，都歡迎與我們聯繫。
            </p>
          </Col>

          {/* 快速連結 */}
          <Col md={4}>
            <h5 className="mb-3">快速連結</h5>
            <ul className="list-unstyled">
              <li className="mb-2">
                <Link to="/" className="text-decoration-none text-muted">
                  首頁
                </Link>
              </li>
              <li className="mb-2">
                <Link to="/profile" className="text-decoration-none text-muted">
                  個人資料
                </Link>
              </li>
              <li className="mb-2">
                <a
                  href="#"
                  className="text-decoration-none text-muted"
                  onClick={(e) => {
                    e.preventDefault();
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                  }}
                >
                  回到頂部
                </a>
              </li>
            </ul>
          </Col>

          {/* 聯絡我們 */}
          <Col md={4}>
            <h5 className="mb-3">聯絡我們</h5>
            <ul className="list-unstyled">
              <li className="mb-2 text-muted">
                <i className="fas fa-envelope me-2"></i>
                support@example.com
              </li>
              <li className="mb-2 text-muted">
                <i className="fas fa-phone me-2"></i>
                +886 123 456 789
              </li>
            </ul>
            <div className="mt-3">
              <a
                href="#"
                className="text-muted me-3"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FontAwesomeIcon icon={faFacebook} size="lg" />
              </a>
              <a
                href="#"
                className="text-muted me-3"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FontAwesomeIcon icon={faTwitter} size="lg" />
              </a>
              <a
                href="#"
                className="text-muted me-3"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FontAwesomeIcon icon={faInstagram} size="lg" />
              </a>
              <a
                href="#"
                className="text-muted"
                target="_blank"
                rel="noopener noreferrer"
              >
                <FontAwesomeIcon icon={faGithub} size="lg" />
              </a>
            </div>
          </Col>
        </Row>

        {/* 版權信息 */}
        <hr className="my-4" />
        <div className="text-center text-muted">
          <p className="mb-0">
            &copy; {currentYear} Your Company Name. All rights reserved.
          </p>
        </div>
      </Container>
    </footer>
  );
};

export default Footer;
